use http::{Response, StatusCode};

pub const CSS: &str = include_str!("admin.css");
pub const HTMX_JS: &str = include_str!("htmx.min.js");

pub fn serve_css() -> Response<String> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/css; charset=utf-8")
        .header("cache-control", "public, max-age=3600")
        .body(CSS.to_string())
        .unwrap()
}

pub fn serve_htmx() -> Response<String> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/javascript; charset=utf-8")
        .header("cache-control", "public, max-age=86400")
        .body(HTMX_JS.to_string())
        .unwrap()
}
