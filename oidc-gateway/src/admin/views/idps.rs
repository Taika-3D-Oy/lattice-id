use maud::{html, Markup};
use crate::admin::layout::{render_layout, AdminSession};
use crate::store::{self, IdentityProvider};
use http::Response;

pub async fn render_idps_page(session: &AdminSession) -> Response<String> {
    let idps = store::list_identity_providers().await.unwrap_or_default();

    let content = html! {
        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { "Identity Providers" }
                p class="page-subtitle" { "Federated social and external OpenID Connect identity sources." }
            }
            div class="page-actions" {
                button class="btn btn-primary"
                       hx-get="/admin/identity-providers/modal/new"
                       hx-target="#modal-container" {
                    "+ Add Identity Provider"
                }
            }
        }

        div class="card" {
            (render_idps_table(&idps))
        }
    };

    render_layout(session, "idps", "Identity Providers", content)
}

pub fn render_idps_table(idps: &[IdentityProvider]) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead {
                    tr {
                        th { "Provider Type" }
                        th { "Client ID" }
                        th { "Status" }
                        th class="actions" { "Actions" }
                    }
                }
                tbody id="idps-table-body" {
                    @if idps.is_empty() {
                        tr {
                            td colspan="4" class="text-muted" style="text-align:center; padding: 24px;" {
                                "No external identity providers configured."
                            }
                        }
                    } @else {
                        @for idp in idps {
                            tr id={"idp-row-" (idp.id)} {
                                td style="font-weight:600;" { (idp.provider_type) }
                                td class="mono" { (idp.client_id) }
                                td {
                                    @if idp.enabled {
                                        span class="badge badge-success" { "Enabled" }
                                    } @else {
                                        span class="badge badge-muted" { "Disabled" }
                                    }
                                }
                                td class="actions" {
                                    button class="btn btn-xs btn-danger"
                                           hx-delete={"/admin/identity-providers/" (idp.id)}
                                           hx-confirm={"Delete identity provider '" (idp.provider_type) "'?"}
                                           hx-target={"#idp-row-" (idp.id)}
                                           hx-swap="outerHTML" {
                                        "Delete"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn render_new_idp_modal() -> Markup {
    html! {
        div class="modal-overlay" onclick="if(event.target===this)closeModal()" {
            div class="modal" {
                h2 class="modal-title" { "Add External Identity Provider" }
                form hx-post="/admin/identity-providers" hx-target="body" {
                    div class="form-group" {
                        label for="provider_type" { "Provider" }
                        select id="provider_type" name="provider_type" {
                            option value="google" { "Google" }
                            option value="github" { "GitHub" }
                            option value="microsoft" { "Microsoft" }
                            option value="oidc" { "Generic OpenID Connect" }
                        }
                    }
                    div class="form-group" {
                        label for="client_id" { "Client ID" }
                        input type="text" id="client_id" name="client_id" required placeholder="OAuth client identifier";
                    }
                    div class="form-group" {
                        label for="client_secret" { "Client Secret" }
                        input type="password" id="client_secret" name="client_secret" required placeholder="OAuth client secret";
                    }
                    div class="form-group" {
                        label {
                            input type="checkbox" name="enabled" value="true" checked;
                            span style="margin-left: 6px;" { "Enable provider immediately" }
                        }
                    }
                    div class="modal-actions" {
                        button type="button" class="btn btn-ghost" onclick="closeModal()" { "Cancel" }
                        button type="submit" class="btn btn-primary" { "Add Provider" }
                    }
                }
            }
        }
    }
}
