use leptos::prelude::*;
use leptos_router::components::*;
use leptos_router::hooks::use_location;
use leptos_router::path;
use gloo_storage::{LocalStorage, Storage};
use crate::auth::AuthContext;
use crate::views;
use crate::api;

// ── Context types ────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct TenantCtx {
    pub tenants: ReadSignal<Vec<api::Tenant>>,
    pub set_tenants: WriteSignal<Vec<api::Tenant>>,
    pub current_id: ReadSignal<String>,
    pub set_current_id: WriteSignal<String>,
}

#[derive(Clone, PartialEq)]
pub enum ToastKind { Success, Error, Info }

#[derive(Clone)]
pub struct Toast { pub id: u32, pub kind: ToastKind, pub message: String }

#[derive(Clone, Copy)]
pub struct ToastCtx {
    pub toasts: ReadSignal<Vec<Toast>>,
    pub set_toasts: WriteSignal<Vec<Toast>>,
}

pub fn show_toast(set_toasts: WriteSignal<Vec<Toast>>, kind: ToastKind, message: impl Into<String>) {
    let id = (js_sys::Date::now() as u32).wrapping_add(js_sys::Math::random() as u32);
    let msg = message.into();
    set_toasts.update(|v| v.push(Toast { id, kind, message: msg }));
    let st = set_toasts;
    wasm_bindgen_futures::spawn_local(async move {
        gloo_timers::future::TimeoutFuture::new(4_500).await;
        st.update(|v| v.retain(|t| t.id != id));
    });
}

// ── Root App ─────────────────────────────────────────────────

#[component]
pub fn App() -> impl IntoView {
    let (token, set_token)           = signal(String::new());
    let (issuer_url, set_issuer_url) = signal(crate::auth::default_issuer_url());
    let (auth_ready, set_auth_ready) = signal(false);
    let (toasts, set_toasts)         = signal(Vec::<Toast>::new());

    let auth_ctx = AuthContext { token, set_token, issuer_url, set_issuer_url, auth_ready, set_auth_ready };
    provide_context(auth_ctx);
    provide_context(ToastCtx { toasts, set_toasts });

    let auth_for_cb = auth_ctx;
    Effect::new(move |_| {
        crate::auth::check_callback(auth_for_cb);
    });

    view! {
        <Router>
            <AppBody/>
            <ToastDisplay/>
        </Router>
    }
}

#[component]
fn AppBody() -> impl IntoView {
    let auth = expect_context::<AuthContext>();
    view! {
        {move || {
            if !auth.auth_ready.get() {
                view! {
                    <div class="loading-screen">
                        <div class="spinner spinner-lg"></div>
                        <p>"Signing in…"</p>
                    </div>
                }.into_any()
            } else if auth.token.get().is_empty() {
                view! { <UnauthShell/> }.into_any()
            } else {
                view! { <AuthShell/> }.into_any()
            }
        }}
    }
}

// ── Unauthenticated shell ────────────────────────────────────

#[component]
fn UnauthShell() -> impl IntoView {
    let (screen, set_screen) = signal(UnauthScreen::Loading);
    Effect::new(move |_| {
        wasm_bindgen_futures::spawn_local(async move {
            for attempt in 0..15u32 {
                if attempt > 0 {
                    gloo_timers::future::TimeoutFuture::new(2_000).await;
                }
                match crate::api::check_bootstrap().await {
                    Ok(true)  => { set_screen.set(UnauthScreen::Bootstrap); return; }
                    Ok(false) => { set_screen.set(UnauthScreen::Login);     return; }
                    Err(_) if attempt < 14 => continue,
                    Err(_)  => { set_screen.set(UnauthScreen::Login);      return; }
                }
            }
        });
    });
    view! {
        {move || match screen.get() {
            UnauthScreen::Loading => view! {
                <div class="loading-screen">
                    <div class="spinner spinner-lg"></div>
                    <p>"Waiting for backend…"</p>
                </div>
            }.into_any(),
            UnauthScreen::Bootstrap => view! {
                <views::bootstrap::BootstrapView on_done=move |()| set_screen.set(UnauthScreen::Login)/>
            }.into_any(),
            UnauthScreen::Login => view! { <views::login::LoginView/> }.into_any(),
        }}
    }
}

#[derive(Clone, Copy, PartialEq)]
enum UnauthScreen { Loading, Bootstrap, Login }

// ── Authenticated shell ──────────────────────────────────────

#[component]
fn AuthShell() -> impl IntoView {
    let auth = expect_context::<AuthContext>();

    let saved_tenant = LocalStorage::get::<String>("lid_current_tenant").unwrap_or_default();
    let (tenants, set_tenants)     = signal(Vec::<api::Tenant>::new());
    let (current_id, set_current_id) = signal(saved_tenant);
    provide_context(TenantCtx { tenants, set_tenants, current_id, set_current_id });

    Effect::new(move |_| {
        let tok = auth.token.get_untracked();
        let cur = current_id.get_untracked();
        wasm_bindgen_futures::spawn_local(async move {
            if let Ok(list) = api::fetch_tenants(&tok).await {
                if cur.is_empty() {
                    if let Some(first) = list.first() {
                        set_current_id.set(first.id.clone());
                        let _ = LocalStorage::set("lid_current_tenant", &first.id);
                    }
                }
                set_tenants.set(list);
            }
        });
    });

    view! { <AppLayout/> }
}

// ── Layout: topbar + sidebar + routed content ────────────────

#[component]
fn AppLayout() -> impl IntoView {
    let auth = expect_context::<AuthContext>();
    let tenant_ctx = expect_context::<TenantCtx>();

    // Tenant switcher handler
    let on_tenant_change = move |ev: web_sys::Event| {
        use wasm_bindgen::JsCast;
        let val = ev.target()
            .and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok())
            .map(|s| s.value())
            .unwrap_or_default();
        tenant_ctx.set_current_id.set(val.clone());
        let _ = LocalStorage::set("lid_current_tenant", &val);
    };

    view! {
        <div class="app-shell">
            // ── Topbar ──
            <header class="topbar">
                <span class="topbar-brand">"⬡ Lattice ID"</span>
                // Tenant switcher (only when tenants loaded)
                {move || {
                    let ts = tenant_ctx.tenants.get();
                    if ts.is_empty() { return view! { <span></span> }.into_any(); }
                    let cur = tenant_ctx.current_id.get();
                    view! {
                        <div class="tenant-switcher">
                            <span class="text-muted" style="font-size:11px">"Tenant:"</span>
                            <select on:change=on_tenant_change>
                                {ts.into_iter().map(|t| {
                                    let selected = t.id == cur;
                                    let id = t.id.clone();
                                    view! { <option value=id selected=selected>{t.display_name.clone()}</option> }
                                }).collect_view()}
                            </select>
                        </div>
                    }.into_any()
                }}
                <span class="topbar-spacer"></span>
                <span class="topbar-issuer">{move || auth.issuer_url.get()}</span>
                <button class="topbar-btn" on:click=move |_| {
                    let _ = LocalStorage::delete("lid_access_token");
                    auth.set_token.set(String::new());
                }>"Sign out"</button>
            </header>

            // ── Sidebar ──
            <Sidebar/>

            // ── Main content with routes ──
            <main class="main-content">
                <Routes fallback=|| view! { <p class="text-muted">"Page not found."</p> }>
                    <Route path=path!("")              view=views::dashboard::DashboardView/>
                    <Route path=path!("tenants")       view=views::tenants::list::TenantListView/>
                    <Route path=path!("tenants/:id")   view=views::tenants::detail::TenantDetailView/>
                    <Route path=path!("clients")       view=views::client_list::ClientListView/>
                    <Route path=path!("clients/:id")   view=views::client_detail::ClientDetailView/>
                    <Route path=path!("users/:id")     view=views::user_detail::UserDetailView/>
                    <Route path=path!("identity-providers") view=views::idp_list::IdpListView/>
                    <Route path=path!("hooks")         view=views::hooks::list::HookListView/>
                    <Route path=path!("hooks/:id")     view=views::hooks::detail::HookDetailView/>
                    <Route path=path!("settings")      view=views::settings::SettingsView/>
                    <Route path=path!("audit")         view=views::audit_log::AuditLogView/>
                    <Route path=path!("account")       view=views::account::AccountView/>
                </Routes>
            </main>
        </div>
    }
}

#[component]
fn Sidebar() -> impl IntoView {
    let tenant_ctx = expect_context::<TenantCtx>();
    let location = use_location();

    let active = move |seg: &'static str| -> &'static str {
        let p = location.pathname.get();
        // Strip possible /admin prefix from path
        let stripped = p.trim_start_matches('/');
        let stripped = stripped
            .strip_prefix("admin/").unwrap_or(stripped)
            .trim_start_matches('/');
        let stripped = if stripped == "admin" { "" } else { stripped };
        if seg.is_empty() {
            if stripped.is_empty() { "sidebar-link active" } else { "sidebar-link" }
        } else if stripped == seg || stripped.starts_with(&format!("{seg}/")) {
            "sidebar-link active"
        } else {
            "sidebar-link"
        }
    };

    view! {
        <nav class="sidebar">
            <div class="sidebar-section-label">"Overview"</div>
            <A href="/" attr:class=move || active("")>"Dashboard"</A>

            <div class="sidebar-divider"></div>
            <div class="sidebar-section-label">"Tenant"</div>
            {move || {
                let cur = tenant_ctx.current_id.get();
                if cur.is_empty() {
                    view! {
                        <span class="sidebar-link text-muted" style="font-style:italic">"No tenant selected"</span>
                    }.into_any()
                } else {
                    let href = format!("/tenants/{cur}");
                    view! {
                        <A href=href attr:class="sidebar-link">"Members"</A>
                    }.into_any()
                }
            }}

            <div class="sidebar-divider"></div>
            <div class="sidebar-section-label">"Global"</div>
            <A href="/tenants"           attr:class=move || active("tenants")>"Tenants"</A>
            <A href="/clients"           attr:class=move || active("clients")>"Clients"</A>
            <A href="/identity-providers" attr:class=move || active("identity-providers")>"Identity Providers"</A>
            <A href="/hooks"             attr:class=move || active("hooks")>"Hooks"</A>
            <A href="/settings"          attr:class=move || active("settings")>"Settings"</A>
            <A href="/audit"             attr:class=move || active("audit")>"Audit Log"</A>

            <div class="sidebar-divider"></div>
            <div class="sidebar-section-label">"Account"</div>
            <A href="/account" attr:class=move || active("account")>"My Account"</A>
        </nav>
    }
}

// ── Toast display ────────────────────────────────────────────

#[component]
fn ToastDisplay() -> impl IntoView {
    let ctx = expect_context::<ToastCtx>();
    view! {
        <div class="toast-container">
            {move || ctx.toasts.get().into_iter().map(|t| {
                let class = match t.kind {
                    ToastKind::Success => "toast toast-success",
                    ToastKind::Error   => "toast toast-error",
                    ToastKind::Info    => "toast toast-info",
                };
                let id = t.id;
                let st = ctx.set_toasts;
                view! {
                    <div class=class>
                        <span>{t.message.clone()}</span>
                        <button class="toast-close" on:click=move |_| {
                            st.update(|v| v.retain(|x| x.id != id));
                        }>"×"</button>
                    </div>
                }
            }).collect_view()}
        </div>
    }
}

