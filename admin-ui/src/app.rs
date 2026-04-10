use leptos::prelude::*;
use leptos_router::components::*;
use leptos_router::path;
use crate::auth::AuthContext;
use crate::views;

/// Root application component.
#[component]
pub fn App() -> impl IntoView {
    // Global auth state provided via context
    let (token, set_token) = signal(String::new());
    let (issuer_url, set_issuer_url) = signal(crate::auth::default_issuer_url());
    let auth_ctx = AuthContext { token, set_token, issuer_url, set_issuer_url };
    provide_context(auth_ctx.clone());

    // Check for OIDC callback on mount
    let auth_for_cb = auth_ctx.clone();
    Effect::new(move |_| {
        crate::auth::check_callback(auth_for_cb.clone());
    });

    view! {
        <Router>
            <div class="app">
                {move || {
                    if token.get().is_empty() {
                        view! { <UnauthenticatedShell/> }.into_any()
                    } else {
                        view! { <AuthenticatedShell/> }.into_any()
                    }
                }}
            </div>
        </Router>
    }
}

/// Shell shown before login (bootstrap check → bootstrap or login).
#[component]
fn UnauthenticatedShell() -> impl IntoView {
    let (screen, set_screen) = signal(UnauthScreen::Loading);

    // Check bootstrap status on mount, retry up to 15 times if backend not ready
    Effect::new(move |_| {
        wasm_bindgen_futures::spawn_local(async move {
            for attempt in 0..15 {
                if attempt > 0 {
                    gloo_timers::future::TimeoutFuture::new(2_000).await;
                }
                match crate::api::check_bootstrap().await {
                    Ok(true) => { set_screen.set(UnauthScreen::Bootstrap); return; }
                    Ok(false) => { set_screen.set(UnauthScreen::Login); return; }
                    Err(_) if attempt < 14 => continue,
                    Err(_) => { set_screen.set(UnauthScreen::Login); return; }
                }
            }
        });
    });

    view! {
        {move || match screen.get() {
            UnauthScreen::Loading => view! {
                <div class="center-screen">
                    <div class="spinner"></div>
                    <p>"Waiting for backend..."</p>
                </div>
            }.into_any(),
            UnauthScreen::Bootstrap => view! {
                <views::bootstrap::BootstrapView on_done=move |()| {
                    set_screen.set(UnauthScreen::Login);
                }/>
            }.into_any(),
            UnauthScreen::Login => view! {
                <views::login::LoginView/>
            }.into_any(),
        }}
    }
}

#[derive(Clone, Copy, PartialEq)]
enum UnauthScreen { Loading, Bootstrap, Login }

/// Authenticated shell with nav bar + routed content.
#[component]
fn AuthenticatedShell() -> impl IntoView {
    let auth_ctx = expect_context::<AuthContext>();
    let issuer = auth_ctx.issuer_url;

    view! {
        <nav>
            <span class="brand">"Lattice-ID"</span>
            <A href="/" attr:class="nav-link">"Clients"</A>
            <A href="/users" attr:class="nav-link">"Users"</A>
            <A href="/idps" attr:class="nav-link">"Identity Providers"</A>
            <A href="/audit" attr:class="nav-link">"Audit Log"</A>
            <span class="spacer"></span>
            <span class="issuer">{move || issuer.get()}</span>
            <button on:click=move |_| {
                auth_ctx.set_token.set(String::new());
            }>"Logout"</button>
        </nav>
        <div class="content">
            <Routes fallback=|| view! { <p>"Page not found."</p> }>
                <Route path=path!("") view=views::client_list::ClientListView/>
                <Route path=path!("clients/:id") view=views::client_detail::ClientDetailView/>
                <Route path=path!("users") view=views::user_list::UserListView/>
                <Route path=path!("users/:id") view=views::user_detail::UserDetailView/>
                <Route path=path!("idps") view=views::idp_list::IdpListView/>
                <Route path=path!("audit") view=views::audit_log::AuditLogView/>
            </Routes>
        </div>
    }
}
