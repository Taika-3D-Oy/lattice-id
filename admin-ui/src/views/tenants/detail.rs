use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use crate::api::{self, Tenant, TenantMember, InviteRequest};
use crate::auth::AuthContext;
use crate::app::{ToastCtx, ToastKind, show_toast};
use crate::util::copy_text;

#[derive(Clone, Copy, PartialEq)]
enum Tab { Members, Invitations, DangerZone }

#[component]
pub fn TenantDetailView() -> impl IntoView {
    let auth   = expect_context::<AuthContext>();
    let toasts = expect_context::<ToastCtx>();
    let params = use_params_map();

    let tenant_id = Memo::new(move |_| params.read().get("id").unwrap_or_default());

    let (tenant, set_tenant) = signal(None::<Tenant>);
    let (members, set_members) = signal(Vec::<TenantMember>::new());
    let (tab, set_tab) = signal(Tab::Members);
    let (loading, set_loading) = signal(true);

    // Invite modal
    let (show_invite, set_show_invite) = signal(false);
    let (inv_email, set_inv_email)     = signal(String::new());
    let (inv_role, set_inv_role)       = signal("member".to_string());
    let (inviting, set_inviting)       = signal(false);
    let (last_token, set_last_token)   = signal(None::<String>);

    // Confirm delete modal
    let (show_delete, set_show_delete) = signal(false);
    let (delete_confirm, set_delete_confirm) = signal(String::new());
    let (deleting, set_deleting)       = signal(false);

    let fetch = {
        let st = toasts.set_toasts;
        move || {
            let tok = auth.token.get_untracked();
            let tid = tenant_id.get_untracked();
            set_loading.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                // Fetch tenant list to find this tenant's details
                if let Ok(list) = api::fetch_tenants(&tok).await {
                    set_tenant.set(list.into_iter().find(|t| t.id == tid));
                }
                match api::fetch_tenant_members(&tok, &tid).await {
                    Ok(ms) => set_members.set(ms),
                    Err(e) => show_toast(st, ToastKind::Error, e.to_string()),
                }
                set_loading.set(false);
            });
        }
    };
    Effect::new(move |_| { fetch(); });

    let on_remove = {
        let st = toasts.set_toasts;
        move |user_id: String| {
            let tok = auth.token.get_untracked();
            let tid = tenant_id.get_untracked();
            let fetch2 = fetch;
            wasm_bindgen_futures::spawn_local(async move {
                match api::remove_tenant_member(&tok, &tid, &user_id).await {
                    Ok(()) => { show_toast(st, ToastKind::Success, "Member removed"); fetch2(); }
                    Err(e) => show_toast(st, ToastKind::Error, e.to_string()),
                }
            });
        }
    };

    let on_invite = {
        let st = toasts.set_toasts;
        move |_| {
            set_inviting.set(true);
            let tok   = auth.token.get_untracked();
            let tid   = tenant_id.get_untracked();
            let email = inv_email.get_untracked();
            let role  = inv_role.get_untracked();
            wasm_bindgen_futures::spawn_local(async move {
                match api::invite_to_tenant(&tok, &tid, &InviteRequest { email, role }).await {
                    Ok(resp) => {
                        show_toast(st, ToastKind::Success, "Invitation sent");
                        set_last_token.set(Some(resp.invite_token));
                        set_inviting.set(false);
                    }
                    Err(e) => {
                        show_toast(st, ToastKind::Error, e.to_string());
                        set_inviting.set(false);
                    }
                }
            });
        }
    };

    let on_delete = {
        let st = toasts.set_toasts;
        move |_| {
            let name_ok = tenant.get().map(|t| t.name == delete_confirm.get()).unwrap_or(false);
            if !name_ok { return; }
            set_deleting.set(true);
            let tok = auth.token.get_untracked();
            let tid = tenant_id.get_untracked();
            wasm_bindgen_futures::spawn_local(async move {
                match api::delete_tenant(&tok, &tid).await {
                    Ok(()) => {
                        show_toast(st, ToastKind::Success, "Tenant deleted");
                        let win = web_sys::window().unwrap();
                        let _ = win.location().set_href("/tenants");
                    }
                    Err(e) => {
                        show_toast(st, ToastKind::Error, e.to_string());
                        set_deleting.set(false);
                    }
                }
            });
        }
    };

    view! {
        <div class="breadcrumb">
            <A href="tenants">"Tenants"</A>
            <span class="text-muted">"›"</span>
            <span>{move || tenant.get().map(|t| t.display_name.clone()).unwrap_or_else(|| tenant_id.get())}</span>
        </div>

        <div class="page-header">
            <div class="page-header-text">
                <div class="page-title">
                    {move || tenant.get().map(|t| t.display_name.clone()).unwrap_or_else(|| tenant_id.get())}
                </div>
                {move || tenant.get().map(|t| view! {
                    <div class="page-subtitle">
                        <span class="mono-sm">{t.name.clone()}</span>
                        " · "
                        <span class={if t.status=="active" { "badge badge-success" } else { "badge badge-muted" }}>{t.status.clone()}</span>
                    </div>
                })}
            </div>
        </div>

        // ── Tabs ──
        <div class="tabs">
            <button class=move || if tab.get() == Tab::Members { "tab active" } else { "tab" }
                on:click=move |_| set_tab.set(Tab::Members)>"Members"</button>
            <button class=move || if tab.get() == Tab::Invitations { "tab active" } else { "tab" }
                on:click=move |_| set_tab.set(Tab::Invitations)>"Invite"</button>
            <button class=move || if tab.get() == Tab::DangerZone { "tab active" } else { "tab" }
                on:click=move |_| set_tab.set(Tab::DangerZone)>"Danger Zone"</button>
        </div>

        // ── Members tab ──
        {move || (tab.get() == Tab::Members).then(|| view! {
            <div>
                <div style="display:flex; gap:8px; margin-bottom:16px;">
                    <button class="btn btn-primary" on:click=move |_| {
                        set_last_token.set(None);
                        set_show_invite.set(true);
                    }>"+ Invite User"</button>
                </div>
                {move || if loading.get() {
                    view! { <div class="spinner"></div> }.into_any()
                } else if members.get().is_empty() {
                    view! {
                        <div class="empty-state">
                            <div class="empty-icon">"👥"</div>
                            <h3>"No members yet"</h3>
                            <p>"Invite users to this tenant."</p>
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
                                    {move || {
                                        let on_remove2 = on_remove;
                                        members.get().into_iter().map(move |m| {
                                            let uid = m.id.clone();
                                            let uid2 = uid.clone();
                                            view! {
                                                <tr>
                                                    <td>{m.email.clone()}</td>
                                                    <td>{m.name.clone()}</td>
                                                    <td><span class="badge badge-accent">{m.role.clone()}</span></td>
                                                    <td class="text-muted">{api::relative_time(m.joined_at)}</td>
                                                    <td class="actions">
                                                        <A href=format!("/admin/users/{uid}") attr:class="btn btn-sm btn-ghost">"Detail"</A>
                                                        <button class="btn btn-sm btn-danger"
                                                            on:click=move |_| on_remove2(uid2.clone())>"Remove"</button>
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
        })}

        // ── Invitations tab ──
        {move || (tab.get() == Tab::Invitations).then(|| view! {
            <div>
                <p class="text-muted mb-4" style="font-size:13px">
                    "Send an invitation link to a new user. They will receive a token to join this tenant."
                </p>
                {move || last_token.get().map(|token| {
                    let link = format!("{}/invite/accept?token={}", "", token);
                    view! {
                        <div class="card" style="border-color: var(--success);">
                            <h3>"✓ Invitation created"</h3>
                            <p style="font-size:12px; color:var(--muted); margin-bottom:8px;">
                                "Share this link with the invitee:"
                            </p>
                            <div style="display:flex; gap:8px; align-items:center;">
                                <code class="mono" style="flex:1; word-break:break-all; font-size:11px;">{token.clone()}</code>
                                <button class="btn btn-sm" on:click=move |_| copy_text(&link)>"Copy link"</button>
                            </div>
                        </div>
                    }
                })}
                <button class="btn btn-primary" on:click=move |_| {
                    set_last_token.set(None);
                    set_show_invite.set(true);
                }>"+ New Invitation"</button>
            </div>
        })}

        // ── Danger zone tab ──
        {move || (tab.get() == Tab::DangerZone).then(|| view! {
            <div class="danger-zone">
                <div class="danger-zone-title">"⚠ Danger Zone"</div>
                <div class="danger-zone-row">
                    <div class="danger-zone-desc">
                        <h4>"Delete this tenant"</h4>
                        <p>"Permanently removes the tenant and all membership records. This cannot be undone."</p>
                    </div>
                    <button class="btn btn-danger" on:click=move |_| set_show_delete.set(true)>
                        "Delete Tenant"
                    </button>
                </div>
            </div>
        })}

        // ── Invite modal ──
        {move || show_invite.get().then(|| view! {
            <div class="modal-overlay" on:click=move |_| set_show_invite.set(false)>
                <div class="modal" on:click=|ev| ev.stop_propagation()>
                    <div class="modal-title">"Invite User"</div>
                    {move || if last_token.get().is_some() {
                        view! {
                            <p class="msg-success">"Invitation sent! Check the Invitations tab for the link."</p>
                        }.into_any()
                    } else {
                        view! { <span></span> }.into_any()
                    }}
                    <div class="form-group">
                        <label>"Email"</label>
                        <input type="email" placeholder="user@example.com"
                            prop:value=inv_email
                            on:input=move |ev| set_inv_email.set(event_target_value(&ev))/>
                    </div>
                    <div class="form-group">
                        <label>"Role"</label>
                        <select on:change=move |ev| set_inv_role.set(event_target_value(&ev))>
                            <option value="member" selected=move || inv_role.get()=="member">"Member"</option>
                            <option value="admin"  selected=move || inv_role.get()=="admin">"Admin"</option>
                        </select>
                    </div>
                    <div class="modal-actions">
                        <button class="btn" on:click=move |_| set_show_invite.set(false)>"Close"</button>
                        <button class="btn btn-primary"
                            disabled=move || inv_email.get().is_empty() || inviting.get()
                            on:click=on_invite>
                            {move || if inviting.get() { "Sending…" } else { "Send Invitation" }}
                        </button>
                    </div>
                </div>
            </div>
        })}

        // ── Delete confirm modal ──
        {move || show_delete.get().then(|| {
            let tname = tenant.get().map(|t| t.name.clone()).unwrap_or_default();
            let tname2 = tname.clone();
            view! {
                <div class="modal-overlay" on:click=move |_| set_show_delete.set(false)>
                    <div class="modal" on:click=|ev| ev.stop_propagation()>
                        <div class="modal-title">"Delete Tenant"</div>
                        <p class="text-muted mb-4" style="font-size:13px">
                            "This action is permanent. All members will lose access."
                        </p>
                        <div class="form-group">
                            <label>"Type "<strong>{tname.clone()}</strong>" to confirm"</label>
                            <input type="text" placeholder=tname.clone()
                                prop:value=delete_confirm
                                on:input=move |ev| set_delete_confirm.set(event_target_value(&ev))/>
                        </div>
                        <div class="modal-actions">
                            <button class="btn" on:click=move |_| set_show_delete.set(false)>"Cancel"</button>
                            <button class="btn btn-danger"
                                disabled=move || delete_confirm.get() != tname2 || deleting.get()
                                on:click=on_delete>
                                {move || if deleting.get() { "Deleting…" } else { "Delete Tenant" }}
                            </button>
                        </div>
                    </div>
                </div>
            }
        })}
    }
}
