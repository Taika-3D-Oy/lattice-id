/// WebAuthn ceremony helpers — single inline_js block so the snippet file
/// is always at a stable position (inline0.js) and never renumbers.
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
function b64url(buf) {
    var s = '', b = new Uint8Array(buf);
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDec(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var b = atob(s), a = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
    return a.buffer;
}
export function webauthn_available() {
    return !!(window.PublicKeyCredential);
}
export async function webauthn_create(optionsJson) {
    var opts = JSON.parse(optionsJson);
    var pk = opts.publicKey;
    pk.challenge = b64urlDec(pk.challenge);
    pk.user.id = b64urlDec(pk.user.id);
    if (pk.excludeCredentials) {
        pk.excludeCredentials = pk.excludeCredentials.map(function(c) {
            c.id = b64urlDec(c.id); return c;
        });
    }
    var cred = await navigator.credentials.create({ publicKey: pk });
    return JSON.stringify({
        clientDataJSON: b64url(cred.response.clientDataJSON),
        attestationObject: b64url(cred.response.attestationObject),
    });
}
export async function webauthn_create_account(optionsJson) {
    return webauthn_create(optionsJson);
}
"#)]
extern "C" {
    pub fn webauthn_available() -> bool;

    #[wasm_bindgen::prelude::wasm_bindgen(catch)]
    pub async fn webauthn_create(options_json: &str) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch)]
    pub async fn webauthn_create_account(options_json: &str) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;
}
