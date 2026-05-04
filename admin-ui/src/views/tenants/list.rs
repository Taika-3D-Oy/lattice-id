use leptos::prelude::*;
use leptos_router::components::A;
use crate::api::{self, Tenant, CreateTenantRequest};
use crate::auth::AuthContext;
use crate::app::{ToastCtx, ToastKind, show_toast};

fn slug_valid(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[component]
pub fn TenantListView() -> impl IntoView {
    let auth = expect_context::<AuthContext>();
    let toast_ctx = expect_context::<ToastCtx>();

    let (tenants, set_tenants) = signal(Vec::<Tenant>::new());
    let (loading, set_loading) = signal(true);
    let (show_modal, set_show_modal) = signal(false);

    // Create form
    let (f_name, set_f_name)         = signal(String::new());
    let (f_display, set_f_display)   = signal(String::new());
    let (creating, set_creating)     = signal(false);

    let fetch = {
        let tok = auth.token;
        let st = toast_ctx.set_toasts;
        move || {
            set_loading.set(true);
            let tok = tok.get_untracked();
            wasm_bindgen_futures::spawn_local(async move {
                match api::fetch_tenants(&tok).await {
                    Ok(list) => { set_tenants.set(list); set_loading.set(false); }
                    Err(e)   => { show_toast(st, ToastKind::Error, e.to_string()); set_loading.set(false); }
                }
            });
        }
    };
    fetch();

    let on_create = {
        let st = toast_ctx.set_toasts;
        move |_| {
            set_creating.set(true);
            let tok  = auth.token.get_untracked();
            let name = f_name.get_untracked();
            let disp = f_display.get_untracked();
            let req  = CreateTenantRequest { name, display_name: disp };
            let fetch2 = fetch;
            wasm_bindgen_futures::spawn_local(async move {
                match api::create_tenant(&tok, &req).await {
                    Ok(_) => {
                        show_toast(st, ToastKind::Success, "Tenant created");
                        set_show_modal.set(false);
                        set_f_name.set(String::new());
                        set_f_display.set(String::new());
                        set_creating.set(false);
                        fetch2();
                    }
                    Err(e) => {
                        show_toast(st, ToastKind::Error, e.to_string());
                        set_creating.set(false);
                    }
                }
            });
        }
    };

    let form_valid = Memo::new(move |_| slug_valid(&f_name.get()) && !f_display.get().is_empty());

    view! {
        <div class="page-header">
            <div class="page-header-text">
                <div class="page-title">"Tenants"</div>
                <div class="page-subtitle">"Isolated workspaces for organisations"</div>
            </div>
            <div class="page-actions">
                <button class="btn btn-primary" on:click=move |_| set_show_modal.set(true)>"+ New Tenant"</button>
            </div>
        </div>

        {move || if loading.get() {
            view! {
                <div class="table-wrap">
                    <table><thead><tr><th>"Name"</th><th>"Display"</th><th>"Status"</th><th>"Created"</th><th></th></tr></thead>
                    <tbody>
                        {(0..3).map(|_| view! {
                            <tr>
                                <td><div class="skeleton skeleton-line w-75"></div></td>
                                <td><div class="skeleton skeleton-line w-50"></div></td>
                                <td><div class="skeleton skeleton-line w-30"></div></td>
                                <td><div class="skeleton skeleton-line w-50"></div></td>
                                <td></td>
                            </tr>
                        }).collect_view()}
                    </tbody></table>
                </div>
            }.into_any()
        } else if tenants.get().is_empty() {
            view! {
                <div class="empty-state">
                    <div class="empty-icon">"🏢"</div>
                    <h3>"No tenants yet"</h3>
                    <p>"Create your first tenant to start managing users."</p>
                    <button class="btn btn-primary" on:click=move |_| set_show_modal.set(true)>"+ Create Tenant"</button>
                </div>
            }.into_any()
        } else {
            view! {
                <div class="table-wrap">
                    <table>
                        <thead><tr>
                            <th>"Slug"</th>
                            <th>"Display Name"</th>
                            <th>"Status"</th>
                            <th>"Created"</th>
                            <th></th>
                        </tr></thead>
                        <tbody>
                            {move || tenants.get().into_iter().map(|t| {
                                let tid = t.id.clone();
                                let status_class = if t.status == "active" { "badge badge-success" } else { "badge badge-muted" };
                                view! {
                                    <tr>
                                        <td class="mono">{t.name.clone()}</td>
                                        <td>{t.display_name.clone()}</td>
                                        <td><span class=status_class>{t.status.clone()}</span></td>
                                        <td class="text-muted">{api::format_timestamp(t.created_at)}</td>
                                        <td class="actions">
                                            <A href=format!("/admin/tenants/{tid}") attr:class="btn btn-sm">"View →"</A>
                                        </td>
                                    </tr>
                                }
                            }).collect_view()}
                        </tbody>
                    </table>
                </div>
            }.into_any()
        }}

        // ── Create modal ──
        {move || show_modal.get().then(|| view! {
            <div class="modal-overlay" on:click=move |_| set_show_modal.set(false)>
                <div class="modal" on:click=|ev| ev.stop_propagation()>
                    <div class="modal-title">"New Tenant"</div>
                    <div class="form-group">
                        <label>"Slug (URL-safe name)"</label>
                        <input type="text" placeholder="e.g. acme-corp"
                            prop:value=f_name
                            on:input=move |ev| set_f_name.set(event_target_value(&ev))/>
                        {move || (!f_name.get().is_empty() && !slug_valid(&f_name.get())).then(||
                            view! { <div class="form-error">"Lowercase letters, digits and hyphens only."</div> }
                        )}
                        <div class="form-hint">"Immutable identifier used in APIs."</div>
                    </div>
                    <div class="form-group">
                        <label>"Display Name"</label>
                        <input type="text" placeholder="e.g. Acme Corp"
                            prop:value=f_display
                            on:input=move |ev| set_f_display.set(event_target_value(&ev))/>
                    </div>
                    <div class="modal-actions">
                        <button class="btn" on:click=move |_| set_show_modal.set(false)>"Cancel"</button>
                        <button class="btn btn-primary"
                            disabled=move || !form_valid.get() || creating.get()
                            on:click=on_create>
                            {move || if creating.get() { "Creating…" } else { "Create Tenant" }}
                        </button>
                    </div>
                </div>
            </div>
        })}
    }
}
