use maud::html;
use crate::admin::layout::{render_layout, AdminSession};
use crate::store;
use http::Response;

pub async fn render_settings_page(session: &AdminSession) -> Response<String> {
    let settings = store::get_runtime_settings().await;

    let content = html! {
        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { "System Settings" }
                p class="page-subtitle" { "Configure global authentication policies and registration controls." }
            }
        }

        div class="card" {
            form hx-post="/admin/settings" hx-target="body" {
                div class="toggle-row" {
                    div class="toggle-label" {
                        h3 { "Public User Registration" }
                        p { "When enabled, unauthenticated visitors can create new user accounts via /register." }
                    }
                    label class="toggle-switch" {
                        input type="checkbox" name="allow_registration" value="true" checked[settings.allow_registration];
                        span class="toggle-track" {}
                    }
                }

                div class="form-actions" style="margin-top: 24px;" {
                    button type="submit" class="btn btn-primary" { "Save Changes" }
                }
            }
        }
    };

    render_layout(session, "settings", "Settings", content)
}
