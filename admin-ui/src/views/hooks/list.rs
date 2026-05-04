use leptos::prelude::*;
use leptos_router::components::A;
use crate::api::{self, Hook, CreateHookRequest};
use crate::auth::AuthContext;
use crate::app::{ToastCtx, ToastKind, show_toast};

#[component]
pub fn HookListView() -> impl IntoView {
    let auth   = expect_context::<AuthContext>();
    let toasts = expect_context::<ToastCtx>();

    let (hooks, set_hooks)       = signal(Vec::<Hook>::new());
    let (loading, set_loading)   = signal(true);
    let (show_modal, set_show_modal) = signal(false);

    let (f_name, set_f_name)   = signal(String::new());
    let (f_trigger, set_f_trigger) = signal("post-login".to_string());
    let (creating, set_creating)   = signal(false);

    let fetch = {
        let st = toasts.set_toasts;
        move || {
            set_loading.set(true);
            let tok = auth.token.get_untracked();
            wasm_bindgen_futures::spawn_local(async move {
                match api::fetch_hooks(&tok).await {
                    Ok(list) => { set_hooks.set(list); set_loading.set(false); }
                    Err(e)   => { show_toast(st, ToastKind::Error, e.to_string()); set_loading.set(false); }
                }
            });
        }
    };
    fetch();

    let on_create = {
        let st = toasts.set_toasts;
        move |_| {
            set_creating.set(true);
            let tok = auth.token.get_untracked();
            let req = CreateHookRequest {
                name: f_name.get_untracked(),
                trigger: f_trigger.get_untracked(),
                script: "// Hook script\n// Access: ctx.user, ctx.claims\n// Return: true to allow, false to deny\ntrue".to_string(),
                enabled: true,
                priority: 0,
            };
            let fetch2 = fetch;
            wasm_bindgen_futures::spawn_local(async move {
                match api::create_hook(&tok, &req).await {
                    Ok(_) => {
                        show_toast(st, ToastKind::Success, "Hook created");
                        set_show_modal.set(false);
                        set_f_name.set(String::new());
                        set_creating.set(false);
                        fetch2();
                    }
                    Err(e) => { show_toast(st, ToastKind::Error, e.to_string()); set_creating.set(false); }
                }
            });
        }
    };

    view! {
        <div class="page-header">
            <div class="page-header-text">
                <div class="page-title">"Hooks"</div>
                <div class="page-subtitle">"Rhai scripts that run at auth events"</div>
            </div>
            <div class="page-actions">
                <button class="btn btn-primary" on:click=move |_| set_show_modal.set(true)>"+ New Hook"</button>
            </div>
        </div>

        {move || if loading.get() {
            view! { <div class="spinner"></div> }.into_any()
        } else if hooks.get().is_empty() {
            view! {
                <div class="empty-state">
                    <div class="empty-icon">"⚙️"</div>
                    <h3>"No hooks configured"</h3>
                    <p>"Hooks let you run custom Rhai scripts at login or registration events."</p>
                    <button class="btn btn-primary" on:click=move |_| set_show_modal.set(true)>"+ New Hook"</button>
                </div>
            }.into_any()
        } else {
            view! {
                <div class="table-wrap">
                    <table>
                        <thead><tr>
                            <th>"Name"</th><th>"Trigger"</th><th>"Enabled"</th><th>"Priority"</th><th>"Version"</th><th></th>
                        </tr></thead>
                        <tbody>
                            {move || hooks.get().into_iter().map(|h| {
                                let hid = h.id.clone();
                                let trigger_class = match h.trigger.as_str() {
                                    "post-login"        => "badge badge-accent",
                                    "post-registration" => "badge badge-info",
                                    _                   => "badge badge-muted",
                                };
                                view! {
                                    <tr>
                                        <td style="font-weight:500">{h.name.clone()}</td>
                                        <td><span class=trigger_class>{h.trigger.clone()}</span></td>
                                        <td>
                                            {if h.enabled {
                                                view! { <span class="badge badge-success">"enabled"</span> }.into_any()
                                            } else {
                                                view! { <span class="badge badge-muted">"disabled"</span> }.into_any()
                                            }}
                                        </td>
                                        <td class="text-muted">{h.priority}</td>
                                        <td class="mono-sm">"v"{h.version}</td>
                                        <td class="actions">
                                            <A href=format!("/admin/hooks/{hid}") attr:class="btn btn-sm">"Edit →"</A>
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
                    <div class="modal-title">"New Hook"</div>
                    <div class="form-group">
                        <label>"Name"</label>
                        <input type="text" placeholder="e.g. Add users to default tenant"
                            prop:value=f_name
                            on:input=move |ev| set_f_name.set(event_target_value(&ev))/>
                    </div>
                    <div class="form-group">
                        <label>"Trigger"</label>
                        <select on:change=move |ev| set_f_trigger.set(event_target_value(&ev))>
                            <option value="post-login"        selected=move || f_trigger.get()=="post-login">"post-login"</option>
                            <option value="post-registration" selected=move || f_trigger.get()=="post-registration">"post-registration"</option>
                        </select>
                        <div class="form-hint">"Script runs after each successful login or new registration."</div>
                    </div>
                    <div class="modal-actions">
                        <button class="btn" on:click=move |_| set_show_modal.set(false)>"Cancel"</button>
                        <button class="btn btn-primary"
                            disabled=move || f_name.get().is_empty() || creating.get()
                            on:click=on_create>
                            {move || if creating.get() { "Creating…" } else { "Create Hook" }}
                        </button>
                    </div>
                </div>
            </div>
        })}
    }
}
