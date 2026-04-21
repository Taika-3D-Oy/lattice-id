/// Copy text to the clipboard using the async Clipboard API.
/// Falls back silently if the API is unavailable (non-HTTPS, old Safari).
pub fn copy_text(text: &str) {
    let window = web_sys::window().unwrap();
    let navigator = window.navigator();
    let clipboard = navigator.clipboard();
    // Fire-and-forget: clipboard writes are best-effort
    let _ = clipboard.write_text(text);
}
