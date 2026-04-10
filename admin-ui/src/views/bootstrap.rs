use leptos::prelude::*;

#[component]
pub fn BootstrapView(
    #[prop(into)] on_done: Callback<()>,
) -> impl IntoView {
    let (email, set_email) = signal(String::new());
    let (name, set_name) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (confirm, set_confirm) = signal(String::new());
    let (submitting, set_submitting) = signal(false);
    let (error, set_error) = signal(Option::<String>::None);

    let valid = Memo::new(move |_| {
        let e = email.get();
        let n = name.get();
        let p = password.get();
        let c = confirm.get();
        !e.is_empty() && e.contains('@') && !n.is_empty() && p.len() >= 8 && p == c
    });

    let on_submit = move |_| {
        set_submitting.set(true);
        set_error.set(None);
        let em = email.get_untracked();
        let nm = name.get_untracked();
        let pw = password.get_untracked();
        wasm_bindgen_futures::spawn_local(async move {
            match crate::api::submit_bootstrap(&em, &nm, &pw).await {
                Ok(()) => on_done.run(()),
                Err(e) => {
                    set_error.set(Some(e.0));
                    set_submitting.set(false);
                }
            }
        });
    };

    view! {
        <div class="center-screen">
            <div class="bootstrap-box">
                <h1>"Welcome to Lattice-ID"</h1>
                <p>"No administrator account exists yet. Create one to get started."</p>

                <div class="form-group">
                    <label>"Name"</label>
                    <input type="text" placeholder="Admin Name"
                        prop:value=name
                        on:input=move |ev| set_name.set(event_target_value(&ev))
                    />
                </div>
                <div class="form-group">
                    <label>"Email"</label>
                    <input type="email" placeholder="admin@example.com"
                        prop:value=email
                        on:input=move |ev| set_email.set(event_target_value(&ev))
                    />
                </div>
                <div class="form-group">
                    <label>"Password"</label>
                    <input type="password" placeholder="Min 8 characters"
                        prop:value=password
                        on:input=move |ev| set_password.set(event_target_value(&ev))
                    />
                </div>
                <div class="form-group">
                    <label>"Confirm Password"</label>
                    <input type="password" placeholder="Repeat password"
                        prop:value=confirm
                        on:input=move |ev| set_confirm.set(event_target_value(&ev))
                    />
                </div>

                {move || {
                    let p = password.get();
                    let c = confirm.get();
                    if !p.is_empty() && !c.is_empty() && p != c {
                        Some(view! { <p class="msg-error">"Passwords do not match"</p> })
                    } else if !p.is_empty() && p.len() < 8 {
                        Some(view! { <p class="msg-error">"Password must be at least 8 characters"</p> })
                    } else {
                        None
                    }
                }}

                {move || error.get().map(|e| view! { <p class="msg-error">{e}</p> })}

                <div class="form-actions">
                    <button
                        class="btn-primary"
                        disabled=move || !valid.get() || submitting.get()
                        on:click=on_submit
                    >
                        {move || if submitting.get() { "Creating..." } else { "Create Administrator" }}
                    </button>
                </div>
            </div>
        </div>
    }
}
