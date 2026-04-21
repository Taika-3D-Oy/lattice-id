use leptos::prelude::*;
use crate::api::{self, AppSettings, UpdateSettingsRequest};
use crate::auth::AuthContext;
use crate::app::{ToastCtx, ToastKind, show_toast};

#[component]
pub fn SettingsView() -> impl IntoView {
    let auth   = expect_context::<AuthContext>();
    let toasts = expect_context::<ToastCtx>();

    let (settings, set_settings)   = signal(None::<AppSettings>);
    let (loading, set_loading)     = signal(true);
    let (saving, set_saving)       = signal(false);
    let (allow_reg, set_allow_reg) = signal(true);

    Effect::new(move |_| {
        let tok = auth.token.get_untracked();
        let st  = toasts.set_toasts;
        wasm_bindgen_futures::spawn_local(async move {
            match api::fetch_settings(&tok).await {
                Ok(s) => {
                    set_allow_reg.set(s.allow_registration);
                    set_settings.set(Some(s));
                    set_loading.set(false);
                }
                Err(e) => { show_toast(st, ToastKind::Error, e.to_string()); set_loading.set(false); }
            }
        });
    });

    let on_save = {
        let st = toasts.set_toasts;
        move |_| {
            set_saving.set(true);
            let tok = auth.token.get_untracked();
            let req = UpdateSettingsRequest { allow_registration: allow_reg.get_untracked() };
            wasm_bindgen_futures::spawn_local(async move {
                match api::update_settings(&tok, &req).await {
                    Ok(s) => {
                        set_allow_reg.set(s.allow_registration);
                        set_settings.set(Some(s));
                        show_toast(st, ToastKind::Success, "Settings saved");
                        set_saving.set(false);
                    }
                    Err(e) => { show_toast(st, ToastKind::Error, e.to_string()); set_saving.set(false); }
                }
            });
        }
    };

    view! {
        <div class="page-header">
            <div class="page-header-text">
                <div class="page-title">"Settings"</div>
                <div class="page-subtitle">"Runtime configuration for Lattice ID"</div>
            </div>
        </div>

        {move || if loading.get() {
            view! { <div class="spinner"></div> }.into_any()
        } else {
            view! {
                <div class="card" style="max-width:600px;">
                    <div class="card-header">
                        <span class="card-title">"Registration"</span>
                    </div>
                    <div class="toggle-row">
                        <div class="toggle-label">
                            <h3>"Allow public registration"</h3>
                            <p>"When enabled, anyone can create an account via /register."</p>
                        </div>
                        <label class="toggle-switch">
                            <input type="checkbox" prop:checked=allow_reg
                                on:change=move |ev| {
                                    use wasm_bindgen::JsCast;
                                    let checked = ev.target()
                                        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                                        .map(|i| i.checked())
                                        .unwrap_or(false);
                                    set_allow_reg.set(checked);
                                }/>
                            <span class="toggle-track"></span>
                        </label>
                    </div>
                    {move || (!allow_reg.get()).then(|| view! {
                        <p class="text-muted mt-2" style="font-size:12px; padding: 8px 0;">
                            "⚠ Registration is disabled. New users can only join via invitation."
                        </p>
                    })}
                    <div style="display:flex; justify-content:flex-end; margin-top:16px;">
                        <button class="btn btn-primary" disabled=move || saving.get() on:click=on_save>
                            {move || if saving.get() { "Saving…" } else { "Save Settings" }}
                        </button>
                    </div>
                </div>
            }.into_any()
        }}
    }
}
