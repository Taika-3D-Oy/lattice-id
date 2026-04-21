//! Outgoing HTTP client helpers built on wasip3 http-compat.

use wasip3::http_compat::{IncomingResponseBody, http_from_wasi_response, http_into_wasi_request};

/// Send an `http::Request<String>` and return an `http::Response<IncomingResponseBody>`.
pub async fn send(
    mut request: http::Request<String>,
) -> Result<http::Response<IncomingResponseBody>, String> {
    // WASI HTTP derives the Host from the URL authority; the `host` header is
    // forbidden in the WASI types, so strip it before conversion.
    request.headers_mut().remove(http::header::HOST);
    let wasi_request =
        http_into_wasi_request(request).map_err(|e| format!("build wasi request: {e:?}"))?;
    let wasi_response = wasip3::http::client::send(wasi_request)
        .await
        .map_err(|e| format!("HTTP request failed: {e:?}"))?;
    http_from_wasi_response(wasi_response).map_err(|e| format!("parse response: {e:?}"))
}

/// Collect body bytes from an incoming body (request or response).
pub async fn collect_body<B>(mut body: B) -> Result<Vec<u8>, String>
where
    B: http_body::Body<Data = bytes::Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    use std::future::poll_fn;
    use std::pin::Pin;

    let mut bytes = Vec::new();
    loop {
        match poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    bytes.extend_from_slice(data);
                }
            }
            Some(Err(e)) => return Err(format!("read body: {e:?}")),
            None => break,
        }
    }
    Ok(bytes)
}

/// Send an HTTP GET request and return the response body as bytes.
pub async fn get_bytes(url: &str, headers: &[(&str, &str)]) -> Result<(u16, Vec<u8>), String> {
    let mut builder = http::Request::builder().method(http::Method::GET).uri(url);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = builder
        .body(String::new())
        .map_err(|e| format!("build request: {e}"))?;

    let response = send(request).await?;
    let status = response.status().as_u16();
    let body = collect_body(response.into_body()).await?;
    Ok((status, body))
}

/// Send an HTTP GET request and return parsed JSON.
pub async fn get_json(url: &str, headers: &[(&str, &str)]) -> Result<serde_json::Value, String> {
    let mut all_headers = vec![("accept", "application/json")];
    all_headers.extend_from_slice(headers);
    let (status, body) = get_bytes(url, &all_headers).await?;
    if !(200..300).contains(&status) {
        return Err(format!("http {status}"));
    }
    serde_json::from_slice(&body).map_err(|e| format!("parse JSON: {e}"))
}

/// Send an HTTP POST request with JSON body and return status + raw bytes.
pub async fn post_json(
    url: &str,
    body: &str,
    extra_headers: &[(&str, &str)],
) -> Result<(u16, Vec<u8>), String> {
    let mut builder = http::Request::builder()
        .method(http::Method::POST)
        .uri(url)
        .header("content-type", "application/json")
        .header("accept", "application/json");
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let request = builder
        .body(body.to_string())
        .map_err(|e| format!("build request: {e}"))?;
    let response = send(request).await?;
    let status = response.status().as_u16();
    let bytes = collect_body(response.into_body()).await?;
    Ok((status, bytes))
}

/// Send an HTTP POST request with form body and return parsed JSON.
pub async fn post_form_json(url: &str, body: &str) -> Result<(u16, serde_json::Value), String> {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(body.to_string())
        .map_err(|e| format!("build request: {e}"))?;

    let response = send(request).await?;
    let status = response.status().as_u16();
    let bytes = collect_body(response.into_body()).await?;
    let json = serde_json::from_slice(&bytes).map_err(|e| format!("parse response: {e}"))?;
    Ok((status, json))
}
