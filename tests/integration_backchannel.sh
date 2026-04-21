#!/usr/bin/env bash
# Test: OIDC Back-Channel Logout E2E (RFC 8613)
#
# Starts a transient HTTP listener, registers an OIDC client pointing at it,
# performs a full auth-code flow, then calls /logout with id_token_hint and
# verifies the listener received a valid logout_token POST.
#
# The test skips gracefully when the gateway cannot reach localhost
# (e.g. inside a container cluster where the listener is unreachable).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

# ── Pick a free port for the logout receiver ──────────────────────────────────
LISTENER_PORT=$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('', 0))
port = s.getsockname()[1]
s.close()
print(port)
PY
)
LISTENER_DIR="$TMP_DIR/bc-listener"
mkdir -p "$LISTENER_DIR"
RECEIVED_FILE="$LISTENER_DIR/received.json"

# ── Start the listener ────────────────────────────────────────────────────────
# Python listener — waits for exactly one POST /bc-logout, records the body.
python3 - "$LISTENER_PORT" "$RECEIVED_FILE" <<'PY' &
import sys, json, threading
from http.server import HTTPServer, BaseHTTPRequestHandler

port    = int(sys.argv[1])
outfile = sys.argv[2]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")
        with open(outfile, "w") as f:
            json.dump({"path": self.path, "body": body}, f)
        self.send_response(200)
        self.end_headers()
        # Shut down after one request
        threading.Thread(target=self.server.shutdown, daemon=True).start()

srv = HTTPServer(("0.0.0.0", port), Handler)
srv.serve_forever()
PY
LISTENER_PID=$!

# Give the server a moment to bind
sleep 0.5

cleanup_listener() {
  if kill -0 "$LISTENER_PID" 2>/dev/null; then
    kill "$LISTENER_PID" 2>/dev/null || true
    wait "$LISTENER_PID" 2>/dev/null || true
  fi
  cleanup
}
trap cleanup_listener EXIT

main() {
  log "=== Back-Channel Logout E2E Test ==="
  wait_for_cluster

  # ── Check if the gateway can reach our listener ──────────────────────────
  # Register a test client pointing at an impossible port first — if the
  # gateway is inside a container it can't reach host localhost anyway.
  # We detect this by seeing whether the gateway can POST to our listener.
  # For simplicity we assume reachable when BASE_URL == localhost.
  local base_host
  base_host=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$BASE_URL').hostname)")
  if [[ "$base_host" != "localhost" && "$base_host" != "127.0.0.1" ]]; then
    log "SKIP: BASE_URL is not localhost ($BASE_URL); backchannel delivery test requires gateway on loopback."
    exit 0
  fi

  # ── Bootstrap admin ───────────────────────────────────────────────────────
  local password="bc-test-pass-$(random_string | head -c 16)"
  local email="bc.$(date +%s)@example.com"
  local admin_token
  admin_token=$(register_and_login_superadmin "$email" "$password" "BCTest")
  [[ -n "$admin_token" ]] || fail "no admin token"

  # ── Register backchannel client ────────────────────────────────────────────
  local bc_logout_uri="http://localhost:${LISTENER_PORT}/bc-logout"
  local client_resp
  client_resp=$(curl -s -X POST "$BASE_URL/api/clients" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"BackChannel Test\",
      \"redirect_uris\": [\"http://localhost:8090/callback\"],
      \"grant_types\": [\"authorization_code\", \"refresh_token\"],
      \"confidential\": false,
      \"backchannel_logout_uri\": \"${bc_logout_uri}\"
    }")
  local client_id
  client_id=$(echo "$client_resp" | python3 -c "import json,sys; print(json.loads(sys.stdin.read())['client_id'])")
  [[ -n "$client_id" ]] || fail "failed to create backchannel client: $client_resp"
  log "Registered client $client_id with backchannel_logout_uri=$bc_logout_uri"

  # ── Full OIDC auth-code flow ───────────────────────────────────────────────
  local verifier challenge
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")

  local auth_body="$TMP_DIR/bc-auth.html"
  local auth_headers="$TMP_DIR/bc-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=${client_id}&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=bctest&nonce=bcnonce&scope=openid+offline_access" \
    "$auth_body" "$auth_headers" >/dev/null
  local session_id
  session_id=$(extract_session_id "$auth_body")
  [[ -n "$session_id" ]] || fail "no session_id in authorize response"

  local login_body="$TMP_DIR/bc-login.txt"
  local login_headers="$TMP_DIR/bc-login.headers"
  local login_status
  login_status=$(curl_capture POST "$BASE_URL/login" "$login_body" "$login_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$email" \
    --data-urlencode "password=$password")
  assert_eq "302" "$login_status" "login"
  local location
  location=$(header_value "$login_headers" location)
  local code
  code=$(url_query_get "$location" code)
  [[ -n "$code" ]] || fail "no auth code in login redirect"

  local tok_body="$TMP_DIR/bc-tok.json"
  local tok_headers="$TMP_DIR/bc-tok.headers"
  curl_capture POST "$BASE_URL/token" "$tok_body" "$tok_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$code" \
    --data-urlencode "code_verifier=$verifier" \
    --data-urlencode "client_id=$client_id" \
    --data-urlencode "redirect_uri=http://localhost:8090/callback" >/dev/null

  local id_token access_token
  id_token=$(python3  -c "import json,sys; print(json.load(open('$tok_body'))['id_token'])")
  access_token=$(python3 -c "import json,sys; print(json.load(open('$tok_body'))['access_token'])")
  [[ -n "$id_token" ]]     || fail "no id_token in token response"
  [[ -n "$access_token" ]] || fail "no access_token in token response"
  log "Got id_token and access_token for user"

  # ── Call /logout with id_token_hint — triggers backchannel notify ──────────
  local enc_id_token
  enc_id_token=$(python3 -c "from urllib.parse import quote; import sys; print(quote(sys.argv[1]))" "$id_token")
  local logout_status
  logout_status=$(curl -sS -o /dev/null -w "%{http_code}" \
    "$BASE_URL/logout?id_token_hint=${enc_id_token}&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A8090%2Fcallback&state=bye")
  # 302 or 200 are both valid (redirect or confirmation page)
  [[ "$logout_status" == "302" || "$logout_status" == "200" ]] \
    || fail "logout returned unexpected status $logout_status"
  log "Logout call succeeded (HTTP $logout_status)"

  # ── Wait for the listener to receive the backchannel POST ─────────────────
  log "Waiting for backchannel logout POST at $bc_logout_uri ..."
  local waited=0
  while [[ ! -f "$RECEIVED_FILE" ]] && (( waited < 10 )); do
    sleep 0.5
    waited=$((waited + 1))
  done

  if [[ ! -f "$RECEIVED_FILE" ]]; then
    fail "backchannel logout POST was not received within 5 seconds"
  fi
  log "Received backchannel POST"

  # ── Verify the logout_token ────────────────────────────────────────────────
  python3 - "$RECEIVED_FILE" "$client_id" "$email" <<'PY'
import json, sys, base64

data = json.load(open(sys.argv[1]))
client_id = sys.argv[2]
assert data["path"] == "/bc-logout", f"wrong path: {data['path']}"

# Parse form body: logout_token=<JWT>
body = data["body"]
assert body.startswith("logout_token="), f"body did not start with logout_token=: {body[:80]}"
jwt_raw = body[len("logout_token="):]
# URL-decode
from urllib.parse import unquote
jwt = unquote(jwt_raw)

# Decode payload (no signature verify in test — that's for security tests)
parts = jwt.split(".")
assert len(parts) == 3, f"expected 3 JWT parts, got {len(parts)}"
hdr_b64, payload_b64, _ = parts
payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))

print(f"  logout_token claims: {json.dumps(payload, indent=2)}")

assert payload["aud"] == client_id, f"aud mismatch: {payload['aud']} != {client_id}"
assert "sub" in payload, "missing sub claim"
assert "iss" in payload, "missing iss claim"
assert "jti" in payload, "missing jti claim"
assert "events" in payload, "missing events claim"
event_key = "http://schemas.openid.net/event/backchannel-logout"
assert event_key in payload["events"], f"missing {event_key}"
assert "nonce" not in payload, "logout_token MUST NOT contain nonce"

hdr = json.loads(base64.urlsafe_b64decode(hdr_b64 + "=="))
assert hdr["alg"] in ("RS256", "ES256"), f"unexpected alg: {hdr['alg']}"

print("  logout_token is structurally valid")
PY
  log "PASS: backchannel logout_token received and validated"

  log "=== Back-Channel Logout E2E: ALL TESTS PASSED ==="
}

main "$@"
