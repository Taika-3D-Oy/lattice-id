use maud::{html, Markup};
use crate::admin::layout::{render_layout, AdminSession};
use crate::store::{self, OidcClient};
use http::Response;

pub async fn render_clients_page(session: &AdminSession) -> Response<String> {
    let clients = store::list_clients().await.unwrap_or_default();

    let content = html! {
        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { "OAuth Clients" }
                p class="page-subtitle" { "Manage applications, redirect URIs, and authentication secrets." }
            }
            div class="page-actions" {
                button class="btn btn-primary"
                       hx-get="/admin/clients/modal/new"
                       hx-target="#modal-container" {
                    "+ Register Client"
                }
            }
        }

        div class="card" {
            (render_clients_table(&clients))
        }
    };

    render_layout(session, "clients", "OAuth Clients", content)
}

pub fn render_clients_table(clients: &[OidcClient]) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead {
                    tr {
                        th { "Client Name" }
                        th { "Client ID" }
                        th { "Type" }
                        th { "Redirect URIs" }
                        th class="actions" { "Actions" }
                    }
                }
                tbody id="clients-table-body" {
                    @if clients.is_empty() {
                        tr {
                            td colspan="5" class="text-muted" style="text-align:center; padding: 24px;" {
                                "No OAuth clients registered yet."
                            }
                        }
                    } @else {
                        @for c in clients {
                            @let is_confidential = c.client_secret.is_some();
                            tr id={"client-row-" (c.client_id)} {
                                td {
                                    a href={"/admin/clients/" (c.client_id)} style="font-weight:600; text-decoration:none; color:inherit;" {
                                        (c.name)
                                    }
                                }
                                td class="mono" {
                                    span class="copy-chip" onclick="copyToClipboard(this, this.innerText)" { (c.client_id) }
                                }
                                td {
                                    @if is_confidential {
                                        span class="badge badge-accent" { "Confidential" }
                                    } @else {
                                        span class="badge badge-muted" { "Public (PKCE)" }
                                    }
                                }
                                td class="mono-sm" {
                                    (c.redirect_uris.len()) " configured"
                                }
                                td class="actions" {
                                    a href={"/admin/clients/" (c.client_id)} class="btn btn-xs" { "Configure →" }
                                    button class="btn btn-xs btn-danger"
                                           hx-delete={"/admin/clients/" (c.client_id)}
                                           hx-confirm={"Delete client application '" (c.name) "'?"}
                                           hx-target={"#client-row-" (c.client_id)}
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

pub fn render_new_client_modal() -> Markup {
    html! {
        div class="modal-overlay" onclick="if(event.target===this)closeModal()" {
            div class="modal modal-lg" {
                h2 class="modal-title" { "Register OAuth Client Application" }
                form hx-post="/admin/clients" hx-target="body" {
                    div class="form-group" {
                        label for="name" { "Application Name" }
                        input type="text" id="name" name="name" required placeholder="Dashboard Web App";
                    }
                    div class="form-group" {
                        label for="redirect_uris" { "Redirect URIs (one per line)" }
                        textarea id="redirect_uris" name="redirect_uris" required placeholder="https://app.example.com/oauth/callback\nhttp://localhost:3000/callback" {}
                    }
                    div class="form-group" {
                        label for="client_type" { "Client Type" }
                        select id="client_type" name="client_type" {
                            option value="confidential" { "Confidential (Generates Client Secret for server-side apps)" }
                            option value="public" { "Public (SPA / Native Mobile App with PKCE)" }
                        }
                    }

                    h3 style="margin-top: 16px; margin-bottom: 8px;" { "Branding & Customization (Optional)" }
                    div class="form-row" {
                        label for="app_name" { "Display Name" }
                        input type="text" id="app_name" name="app_name" placeholder="Custom Login Title";
                    }
                    div class="form-row" {
                        label for="logo_url" { "Logo URL" }
                        input type="text" id="logo_url" name="logo_url" placeholder="https://example.com/logo.svg";
                    }
                    div class="form-row" {
                        label for="primary_color" { "Brand Color" }
                        input type="text" id="primary_color" name="primary_color" placeholder="#3b82f6";
                    }

                    div class="modal-actions" {
                        button type="button" class="btn btn-ghost" onclick="closeModal()" { "Cancel" }
                        button type="submit" class="btn btn-primary" { "Register Application" }
                    }
                }
            }
        }
    }
}

pub async fn render_client_detail_page(session: &AdminSession, client: &OidcClient) -> Response<String> {
    let redirect_uris_text = client.redirect_uris.join("\n");
    let is_confidential = client.client_secret.is_some();

    let content = html! {
        div class="breadcrumb" {
            a href="/admin/clients" { "Clients" }
            span { "/" }
            span { (client.name) }
        }

        div class="page-header" {
            div class="page-header-text" {
                h1 class="page-title" { (client.name) }
                p class="page-subtitle" {
                    "Client ID: " span class="copy-chip" onclick="copyToClipboard(this, this.innerText)" { (client.client_id) }
                }
            }
        }

        // ── Credentials Card ──
        div class="card" {
            div class="card-header" {
                span class="card-title" { "Client Credentials" }
            }
            div class="detail-grid" {
                div class="label" { "Client ID" }
                div class="value" {
                    span class="copy-chip" onclick="copyToClipboard(this, this.innerText)" { (client.client_id) }
                }

                div class="label" { "Client Type" }
                div class="value" {
                    @if is_confidential {
                        span class="badge badge-accent" { "Confidential" }
                    } @else {
                        span class="badge badge-muted" { "Public (PKCE)" }
                    }
                }

                @if let Some(ref secret) = client.client_secret {
                    div class="label" { "Client Secret" }
                    div class="value" {
                        div class="reveal-field" {
                            span class="mono" { (secret) }
                            button class="btn btn-xs" onclick="copyToClipboard(this, this.previousElementSibling.innerText)" { "Copy" }
                            button class="btn btn-xs btn-danger"
                                   hx-post={"/admin/clients/" (client.client_id) "/rotate-secret"}
                                   hx-confirm="Rotate secret? Any services using the old secret will fail immediately."
                                   hx-target="body" {
                                "Rotate Secret"
                            }
                        }
                    }
                }
            }
        }

        // ── Redirect URIs Card ──
        div class="card" {
            div class="card-header" {
                span class="card-title" { "Allowed Redirect URIs" }
            }
            form hx-post={"/admin/clients/" (client.client_id) "/redirect-uris"} hx-target="body" {
                div class="form-group" {
                    textarea name="redirect_uris" rows="4" { (redirect_uris_text) }
                    div class="form-hint" { "One URL per line. Absolute HTTP/HTTPS URLs." }
                }
                button type="submit" class="btn btn-primary" { "Save Redirect URIs" }
            }
        }

        // ── Danger Zone ──
        div class="danger-zone" {
            div class="danger-zone-title" { "Danger Zone" }
            div class="danger-zone-row" {
                div class="danger-zone-desc" {
                    h4 { "Delete this OAuth client" }
                    p { "Permanently revoke client credentials. Applications will not be able to authenticate users." }
                }
                button class="btn btn-danger"
                       hx-delete={"/admin/clients/" (client.client_id)}
                       hx-confirm={"Permanently delete client '" (client.name) "'?"}
                       hx-target="body" {
                    "Delete Client"
                }
            }
        }
    };

    render_layout(session, "clients", &format!("Client: {}", client.name), content)
}
