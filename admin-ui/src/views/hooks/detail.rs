use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use crate::api::{self, Hook, HookVersion, HookTestResult, UpdateHookRequest};
use crate::auth::AuthContext;
use crate::app::{ToastCtx, ToastKind, show_toast};

#[component]
pub fn HookDetailView() -> impl IntoView {
    let auth   = expect_context::<AuthContext>();
    let toasts = expect_context::<ToastCtx>();
    let params = use_params_map();
    let hook_id = Memo::new(move |_| params.read().get("id").unwrap_or_default());

    let (hook, set_hook)             = signal(None::<Hook>);
    let (loading, set_loading)       = signal(true);
    let (saving, set_saving)         = signal(false);
    let (testing, set_testing)       = signal(false);
    let (versions, set_versions)     = signal(Vec::<HookVersion>::new());
    let (test_result, set_test_result) = signal(None::<HookTestResult>);

    // Editable fields
    let (f_name, set_f_name)       = signal(String::new());
    let (f_trigger, set_f_trigger) = signal(String::new());
    let (f_script, set_f_script)   = signal(String::new());
    let (f_enabled, set_f_enabled) = signal(true);
    let (f_priority, set_f_priority) = signal(0i32);

    let is_dirty = Memo::new(move |_| {
        hook.get().map(|h| {
            h.name    != f_name.get()    ||
            h.trigger != f_trigger.get() ||
            h.script  != f_script.get()  ||
            h.enabled != f_enabled.get() ||
            h.priority != f_priority.get()
        }).unwrap_or(false)
    });

    let fetch = {
        let st = toasts.set_toasts;
        move || {
            set_loading.set(true);
            let tok = auth.token.get_untracked();
            let hid = hook_id.get_untracked();
            wasm_bindgen_futures::spawn_local(async move {
                match api::fetch_hooks(&tok).await {
                    Ok(list) => {
                        if let Some(h) = list.into_iter().find(|h| h.id == hid) {
                            set_f_name.set(h.name.clone());
                            set_f_trigger.set(h.trigger.clone());
                            set_f_script.set(h.script.clone());
                            set_f_enabled.set(h.enabled);
                            set_f_priority.set(h.priority);
                            set_hook.set(Some(h));
                        }
                        set_loading.set(false);
                    }
                    Err(e) => { show_toast(st, ToastKind::Error, e.to_string()); set_loading.set(false); }
                }
                if let Ok(vs) = api::fetch_hook_versions(&tok, &hid).await {
                    let mut vs = vs;
                    vs.sort_by(|a, b| b.version.cmp(&a.version));
                    set_versions.set(vs);
                }
            });
        }
    };
    Effect::new(move |_| { fetch(); });

    let on_save = {
        let st = toasts.set_toasts;
        move |_| {
            set_saving.set(true);
            let tok = auth.token.get_untracked();
            let hid = hook_id.get_untracked();
            let req = UpdateHookRequest {
                name: f_name.get_untracked(),
                trigger: f_trigger.get_untracked(),
                script: f_script.get_untracked(),
                enabled: f_enabled.get_untracked(),
                priority: f_priority.get_untracked(),
            };
            let fetch2 = fetch;
            wasm_bindgen_futures::spawn_local(async move {
                match api::update_hook(&tok, &hid, &req).await {
                    Ok(_)  => { show_toast(st, ToastKind::Success, "Hook saved"); set_saving.set(false); fetch2(); }
                    Err(e) => { show_toast(st, ToastKind::Error, e.to_string()); set_saving.set(false); }
                }
            });
        }
    };

    let on_discard = move |_| {
        if let Some(h) = hook.get() {
            set_f_name.set(h.name);
            set_f_trigger.set(h.trigger);
            set_f_script.set(h.script);
            set_f_enabled.set(h.enabled);
            set_f_priority.set(h.priority);
        }
    };

    let on_test = {
        let st = toasts.set_toasts;
        move |_| {
            set_testing.set(true);
            set_test_result.set(None);
            let tok = auth.token.get_untracked();
            let hid = hook_id.get_untracked();
            wasm_bindgen_futures::spawn_local(async move {
                match api::test_hook(&tok, &hid).await {
                    Ok(r)  => { set_test_result.set(Some(r)); set_testing.set(false); }
                    Err(e) => { show_toast(st, ToastKind::Error, e.to_string()); set_testing.set(false); }
                }
            });
        }
    };

    let on_delete = {
        let st = toasts.set_toasts;
        move |_| {
            if !web_sys::window().and_then(|w| w.confirm_with_message("Delete this hook?").ok()).unwrap_or(false) {
                return;
            }
            let tok = auth.token.get_untracked();
            let hid = hook_id.get_untracked();
            wasm_bindgen_futures::spawn_local(async move {
                match api::delete_hook(&tok, &hid).await {
                    Ok(()) => {
                        show_toast(st, ToastKind::Success, "Hook deleted");
                        let _ = web_sys::window().unwrap().location().set_href("/hooks");
                    }
                    Err(e) => show_toast(st, ToastKind::Error, e.to_string()),
                }
            });
        }
    };

    // Line numbers for code editor
    let line_count = Memo::new(move |_| {
        let n = f_script.get().lines().count().max(1);
        n
    });

    view! {
        <div class="breadcrumb">
            <A href="/hooks">"Hooks"</A>
            <span class="text-muted">"›"</span>
            <span>{move || hook.get().map(|h| h.name.clone()).unwrap_or_else(|| hook_id.get())}</span>
        </div>

        {move || if loading.get() {
            view! { <div class="spinner"></div> }.into_any()
        } else if hook.get().is_none() {
            view! { <p class="text-muted">"Hook not found."</p> }.into_any()
        } else { view! {
            <div>
                <div class="split-pane">
                    // ── Left: editor + metadata ──
                    <div>
                        <div class="card">
                            <div class="card-header">
                                <span class="card-title">"Script"</span>
                                {move || hook.get().map(|h| view! {
                                    <span class="mono-sm">"v"{h.version}" · "{h.script_hash[..8].to_string()}</span>
                                })}
                            </div>
                            <div class="code-editor-wrap">
                                <div class="code-editor-inner">
                                    <div class="code-line-nums">
                                        {move || (1..=line_count.get()).map(|n| view! {
                                            <span>{n}</span>
                                        }).collect_view()}
                                    </div>
                                    <textarea class="code-editor-area"
                                        spellcheck="false"
                                        prop:value=f_script
                                        on:input=move |ev| set_f_script.set(event_target_value(&ev))>
                                    </textarea>
                                </div>
                            </div>
                        </div>

                        <div class="card">
                            <div class="card-header"><span class="card-title">"Metadata"</span></div>
                            <div class="form-group">
                                <label>"Name"</label>
                                <input type="text" prop:value=f_name
                                    on:input=move |ev| set_f_name.set(event_target_value(&ev))/>
                            </div>
                            <div class="form-group">
                                <label>"Trigger"</label>
                                <select on:change=move |ev| set_f_trigger.set(event_target_value(&ev))>
                                    <option value="post-login"        selected=move || f_trigger.get()=="post-login">"post-login"</option>
                                    <option value="post-registration" selected=move || f_trigger.get()=="post-registration">"post-registration"</option>
                                </select>
                            </div>
                            <div style="display:flex; gap:16px; align-items:center;">
                                <label class="flex" style="gap:8px; cursor:pointer;">
                                    <input type="checkbox" prop:checked=f_enabled
                                        on:change=move |ev| {
                                            use wasm_bindgen::JsCast;
                                            let checked = ev.target()
                                                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                                                .map(|i| i.checked())
                                                .unwrap_or(false);
                                            set_f_enabled.set(checked);
                                        }/>
                                    <span>"Enabled"</span>
                                </label>
                                <div class="form-group" style="margin:0; flex:1;">
                                    <label>"Priority"</label>
                                    <input type="number" prop:value=f_priority
                                        on:input=move |ev| {
                                            if let Ok(n) = event_target_value(&ev).parse::<i32>() {
                                                set_f_priority.set(n);
                                            }
                                        }/>
                                </div>
                            </div>
                        </div>

                        // ── Danger zone ──
                        <div class="danger-zone">
                            <div class="danger-zone-title">"⚠ Danger Zone"</div>
                            <div class="danger-zone-row">
                                <div class="danger-zone-desc">
                                    <h4>"Delete hook"</h4>
                                    <p>"Permanently removes this hook and all version history."</p>
                                </div>
                                <button class="btn btn-danger" on:click=on_delete>"Delete"</button>
                            </div>
                        </div>
                    </div>

                    // ── Right: test runner + versions ──
                    <div>
                        <div class="card">
                            <div class="card-header">
                                <span class="card-title">"Test Runner"</span>
                                <button class="btn btn-sm btn-primary"
                                    disabled=move || testing.get()
                                    on:click=on_test>
                                    {move || if testing.get() { "Running…" } else { "▶ Run" }}
                                </button>
                            </div>
                            <p class="text-muted" style="font-size:12px; margin-bottom:8px;">
                                "Runs the current saved script with a mock context."
                            </p>
                            {move || test_result.get().map(|r| {
                                let mut out = String::new();
                                if r.success {
                                    out.push_str("✓ PASSED\n");
                                } else {
                                    out.push_str(&format!("✗ FAILED\n"));
                                    if let Some(reason) = &r.deny_reason {
                                        out.push_str(&format!("  deny_reason: {reason}\n"));
                                    }
                                }
                                if let Some(msgs) = &r.log_messages {
                                    for m in msgs { out.push_str(&format!("[log] {m}\n")); }
                                }
                                if let Some(err) = &r.error {
                                    out.push_str(&format!("[error] {err}\n"));
                                }
                                if let Some(claims) = &r.extra_claims {
                                    out.push_str(&format!("[claims] {claims}\n"));
                                }
                                let class = if r.success { "test-output test-ok" } else { "test-output test-err" };
                                view! { <div class=class>{out}</div> }
                            })}
                        </div>

                        <div class="card">
                            <div class="card-header"><span class="card-title">"Version History"</span></div>
                            {move || if versions.get().is_empty() {
                                view! { <p class="text-muted" style="font-size:12px;">"No version history yet."</p> }.into_any()
                            } else {
                                view! {
                                    <div>
                                        {versions.get().into_iter().map(|v| view! {
                                            <div class="version-item">
                                                <span class="version-num">"v"{v.version}</span>
                                                <div class="version-meta">
                                                    <div>{v.changed_by.clone()}</div>
                                                    <div>{api::relative_time(v.changed_at)}</div>
                                                    <div class="mono-sm">{v.script_hash[..8].to_string()}</div>
                                                </div>
                                            </div>
                                        }).collect_view()}
                                    </div>
                                }.into_any()
                            }}
                        </div>
                    </div>
                </div>

                // ── Save bar ──
                {move || is_dirty.get().then(|| view! {
                    <div class="save-bar">
                        <span class="save-bar-msg">"You have unsaved changes."</span>
                        <button class="btn" on:click=on_discard>"Discard"</button>
                        <button class="btn btn-primary" disabled=move || saving.get() on:click=on_save>
                            {move || if saving.get() { "Saving…" } else { "Save" }}
                        </button>
                    </div>
                })}
            </div>
        }.into_any()}}
    }
}
