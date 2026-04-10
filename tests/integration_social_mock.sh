#!/usr/bin/env bash
# Test: Google social login flow with mocked Google endpoints (3.7)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

MOCK_PID=""

cleanup_all() {
  if [[ -n "${MOCK_PID:-}" ]] && kill -0 "$MOCK_PID" 2>/dev/null; then
    kill "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
  fi
  cleanup
}

trap cleanup_all EXIT

build_mock_google_material() {
  local private_key="$TMP_DIR/mock-google-private.pem"
  local public_key="$TMP_DIR/mock-google-public.pem"
  local jwks_json="$TMP_DIR/mock-google-jwks.json"
  local token_json="$TMP_DIR/mock-google-token.json"
  local signing_input="$TMP_DIR/mock-google-signing-input.txt"
  local signature_bin="$TMP_DIR/mock-google-signature.bin"

  openssl genrsa -out "$private_key" 2048 >/dev/null 2>&1
  openssl rsa -in "$private_key" -pubout -out "$public_key" >/dev/null 2>&1

  python3 - "$public_key" "$jwks_json" <<'PY'
import base64
import json
import re
import subprocess
import sys

public_key, jwks_json = sys.argv[1], sys.argv[2]
text = subprocess.check_output([
    "openssl", "rsa", "-pubin", "-in", public_key, "-text", "-noout"
], text=True)
modulus_match = re.search(r"Modulus:\n((?:\s+[0-9a-f:]+\n)+)", text, re.IGNORECASE)
exponent_match = re.search(r"Exponent:\s+(\d+)", text)
if not modulus_match or not exponent_match:
    raise SystemExit("failed to parse openssl RSA public key output")
modulus_hex = "".join(line.strip().replace(":", "") for line in modulus_match.group(1).splitlines())
if modulus_hex.startswith("00"):
    modulus_hex = modulus_hex[2:]
modulus = bytes.fromhex(modulus_hex)
exponent = int(exponent_match.group(1)).to_bytes((int(exponent_match.group(1)).bit_length() + 7) // 8, "big")
def b64u(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
with open(jwks_json, "w", encoding="utf-8") as handle:
    json.dump({
        "keys": [{
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "mock-google-kid",
            "n": b64u(modulus),
            "e": b64u(exponent),
        }]
    }, handle)
PY

  python3 - "$signing_input" <<'PY'
import base64
import json
import sys
import time

signing_input = sys.argv[1]
header = {"alg": "RS256", "kid": "mock-google-kid", "typ": "JWT"}
payload = {
    "iss": "https://accounts.google.com",
    "aud": "mock-google-client",
    "sub": "google-sub-123",
    "email": "social.user@example.com",
    "name": "Mock Google User",
    "email_verified": True,
    "nonce": "google-nonce",
    "iat": int(time.time()),
    "exp": int(time.time()) + 600,
}
def b64u(value):
    data = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
with open(signing_input, "w", encoding="utf-8") as handle:
    handle.write(f"{b64u(header)}.{b64u(payload)}")
PY

  openssl dgst -sha256 -sign "$private_key" -out "$signature_bin" "$signing_input"

  python3 - "$signing_input" "$signature_bin" "$token_json" <<'PY'
import base64
import json
import sys

signing_input, signature_bin, token_json = sys.argv[1], sys.argv[2], sys.argv[3]
with open(signing_input, "r", encoding="utf-8") as handle:
    prefix = handle.read().strip()
with open(signature_bin, "rb") as handle:
    signature = base64.urlsafe_b64encode(handle.read()).decode("ascii").rstrip("=")
with open(token_json, "w", encoding="utf-8") as handle:
    json.dump({"id_token": f"{prefix}.{signature}"}, handle)
PY

  echo "$token_json|$jwks_json"
}

start_mock_google_server() {
  local token_json="$1"
  local jwks_json="$2"
  local port="$3"
  python3 "$SCRIPT_DIR/google_mock_server.py" --port "$port" --token-json "$token_json" --jwks-json "$jwks_json" >"$TMP_DIR/mock-google.log" 2>&1 &
  MOCK_PID=$!
  for _ in {1..20}; do
    if python3 - "$port" <<'PY'
import socket
import sys

sock = socket.socket()
try:
    sock.connect(("127.0.0.1", int(sys.argv[1])))
    sys.exit(0)
except OSError:
    sys.exit(1)
finally:
    sock.close()
PY
    then
      return 0
    fi
    sleep 0.2
  done
  fail "mock Google server did not start"
}

create_identity_provider() {
  local admin_token="$1"
  local body_file="$TMP_DIR/google-idp.json"
  local headers_file="$TMP_DIR/google-idp.headers"
  local status
  status=$(curl_capture POST "$BASE_URL/api/identity-providers" "$body_file" "$headers_file" \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer $admin_token" \
    -d '{"provider_type":"google","client_id":"mock-google-client","client_secret":"mock-google-secret","enabled":true}')
  assert_eq 201 "$status" "google identity provider creation"
}

main() {
  log "Starting mocked Google social login integration test..."

  local mock_port=9911
  local material
  material=$(build_mock_google_material)
  local token_json="${material%%|*}"
  local jwks_json="${material#*|}"
  start_mock_google_server "$token_json" "$jwks_json" "$mock_port"

  export LATTICE_ID_GOOGLE_AUTH_URL="http://127.0.0.1:${mock_port}/o/oauth2/v2/auth"
  export LATTICE_ID_GOOGLE_TOKEN_URL="http://127.0.0.1:${mock_port}/token"
  export LATTICE_ID_GOOGLE_JWKS_URL="http://127.0.0.1:${mock_port}/certs"

  start_wash_dev

  local admin_email="social.admin.$(date +%s)@example.com"
  local admin_password='changeme123'
  local admin_token
  admin_token=$(register_and_login_superadmin "$admin_email" "$admin_password" "Social Admin")
  assert_ne "" "$admin_token" "admin access token"

  create_identity_provider "$admin_token"

  local verifier challenge authorize_body authorize_headers session_id
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  authorize_body="$TMP_DIR/social-authorize.html"
  authorize_headers="$TMP_DIR/social-authorize.headers"
  status=$(curl_capture GET "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8000/callback&scope=openid+email+profile&code_challenge=$challenge&code_challenge_method=S256&state=social-state&nonce=google-nonce" "$authorize_body" "$authorize_headers")
  assert_eq 200 "$status" "social authorize page"
  session_id=$(extract_session_id "$authorize_body")

  local google_start_body="$TMP_DIR/google-start.txt"
  local google_start_headers="$TMP_DIR/google-start.headers"
  status=$(curl_capture GET "$BASE_URL/auth/google?session_id=$session_id" "$google_start_body" "$google_start_headers")
  assert_eq 302 "$status" "google auth start"
  local google_location
  google_location=$(header_value "$google_start_headers" location)
  [[ "$google_location" == http://127.0.0.1:${mock_port}/o/oauth2/v2/auth* ]] || fail "unexpected google redirect url: $google_location"
  assert_eq "$session_id" "$(url_query_get "$google_location" state)" "google redirect state"
  assert_eq "google-nonce" "$(url_query_get "$google_location" nonce)" "google redirect nonce"

  local callback_body="$TMP_DIR/google-callback.html"
  local callback_headers="$TMP_DIR/google-callback.headers"
  status=$(curl_capture GET "$BASE_URL/auth/google/callback?code=mock-auth-code&state=$session_id" "$callback_body" "$callback_headers")
  assert_eq 302 "$status" "google callback"
  local callback_location
  callback_location=$(header_value "$callback_headers" location)
  local code
  code=$(url_query_get "$callback_location" code)
  assert_ne "" "$code" "social login authorization code"

  local token_body="$TMP_DIR/social-token.json"
  local token_headers="$TMP_DIR/social-token.headers"
  status=$(curl_capture POST "$BASE_URL/token" "$token_body" "$token_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode "code=$code" \
    --data-urlencode "code_verifier=$verifier" \
    --data-urlencode 'redirect_uri=http://localhost:8000/callback' \
    --data-urlencode 'client_id=lid-admin')
  assert_eq 200 "$status" "social token exchange"
  local access_token
  access_token=$(json_get "$token_body" access_token)

  local userinfo_body="$TMP_DIR/social-userinfo.json"
  local userinfo_headers="$TMP_DIR/social-userinfo.headers"
  status=$(curl_capture GET "$BASE_URL/userinfo" "$userinfo_body" "$userinfo_headers" \
    -H "Authorization: Bearer $access_token")
  assert_eq 200 "$status" "social userinfo"
  assert_eq 'social.user@example.com' "$(json_get "$userinfo_body" email)" "social user email"
  assert_eq 'Mock Google User' "$(json_get "$userinfo_body" name)" "social user name"

  log "PASS: mocked Google social login flow succeeded"
}

main