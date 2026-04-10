/// URL-decode a percent-encoded string (handles %XX and + as space).
pub fn url_decode(s: &str) -> String {
    let mut result = Vec::with_capacity(s.len());
    let mut bytes = s.as_bytes().iter();
    while let Some(&b) = bytes.next() {
        if b == b'%' {
            if let (Some(&h), Some(&l)) = (bytes.next(), bytes.next())
                && let (Some(hv), Some(lv)) = (hex_val(h), hex_val(l))
            {
                result.push(hv << 4 | lv);
                continue;
            }
            result.push(b);
        } else if b == b'+' {
            result.push(b' ');
        } else {
            result.push(b);
        }
    }
    String::from_utf8_lossy(&result).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse a URL query string into key-value pairs with URL decoding.
pub fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = url_decode(parts.next()?);
            let value = url_decode(parts.next().unwrap_or(""));
            Some((key, value))
        })
        .collect()
}

/// Parse a URL-encoded form body into key-value pairs with URL decoding.
pub fn parse_form(body: &[u8]) -> Vec<(String, String)> {
    let s = std::str::from_utf8(body).unwrap_or("");
    parse_query(s)
}

/// Look up a value in a parsed form/query.
pub fn form_value<'a>(form: &'a [(String, String)], key: &str) -> Option<&'a str> {
    form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// Escape HTML special characters to prevent XSS.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Percent-encode a string for use in URLs (RFC 3986 unreserved characters pass through).
pub fn percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{b:02X}"));
            }
        }
    }
    result
}

/// Validate a hex color string (e.g., "#2563eb"). Returns true if valid.
pub fn is_valid_hex_color(s: &str) -> bool {
    let s = s.trim();
    s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// Sanitize a color value: return it if it's a valid hex color, otherwise return the fallback.
pub fn sanitize_color(color: Option<&str>, fallback: &str) -> String {
    match color {
        Some(c) if is_valid_hex_color(c) => c.to_string(),
        _ => fallback.to_string(),
    }
}

/// Validate that a URL uses http:// or https:// scheme only.
pub fn is_safe_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}
