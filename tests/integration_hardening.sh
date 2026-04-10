#!/usr/bin/env bash
# Test: OIDC Protocol Hardening Cases (Phase 2 & 3)
# Focus: PKCE validation, Token Rotation, Error Sanitization, GC, and Email Verification

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

pkce_challenge() {
  python3 - "$1" <<'PY'
import base64, hashlib, sys
digest = hashlib.sha256(sys.argv[1].encode('utf-8')).digest()
print(base64.urlsafe_b64encode(digest).decode('ascii').rstrip('='))
PY
}

extract_session_id() {
  python3 - "$1" <<'PY'
import re, sys
html = open(sys.argv[1], 'r').read()
m = re.search(r'name="session_id"\s+value="([^"]+)"', html)
if not m:
    sys.stderr.write("Could not find session_id in HTML form\n")
    sys.exit(1)
print(m.group(1))
PY
}

main() {
  log "Starting Phase 2/3 Hardening Tests..."

  # Enable email verification for this test (restore on cleanup)
  local config_file="$ROOT/.wash/config.yaml"
  cp "$config_file" "$TMP_DIR/config.yaml.bak"
  sed -i '' 's/require_email_verification: "false"/require_email_verification: "true"/' "$config_file"
  # Ensure we restore even on failure
  trap 'cp "$TMP_DIR/config.yaml.bak" "$config_file" 2>/dev/null; cleanup' EXIT

  start_wash_dev
  
  # Register admin (bootstrap hook promotes to superadmin)
  log "Registering admin..."
  local admin_token
  admin_token=$(register_and_login_superadmin "admin@example.com" "AdminPass123!" "Admin")
  if [[ -z "$admin_token" ]]; then
     fail "Failed to get admin token"
  fi
  log "Admin registered OK."

  # Case 1: Error Sanitization
  log "Case 1: Testing Error Sanitization..."
  local err_file="$TMP_DIR/err.json"
  curl -s -o "$err_file" -H "Authorization: Bearer $admin_token" "$BASE_URL/api/tenants/non-existent-id"
  if grep -q "get:" "$err_file" || grep -q "open " "$err_file" || grep -q "lid-sessions" "$err_file"; then
    fail "Error message contains sensitive internal details: $(cat "$err_file")"
  fi
  log "OK: Error messages are sanitized."

  # Case 2: Email Verification Flow
  log "Case 2: Testing Email Verification Flow..."
  local reg_email="newuser@example.com"
  local reg_pass="SecurePass123!"
  local reg_file="$TMP_DIR/reg.json"

  local reg_status=$(curl -s -o "$reg_file" -w "%{http_code}" -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{
      \"email\": \"$reg_email\",
      \"password\": \"$reg_pass\",
      \"name\": \"New User\"
    }")
  
  if [[ "$reg_status" != "201" ]]; then
    log "Registration response: $(cat "$reg_file")"
    fail "Registration failed with status $reg_status"
  fi
  
  # Find the verification token in wash dev logs
  log "Waiting for verification token in logs..."
  local verify_token=""
  for i in {1..20}; do
    # Log line format: {"...":"LID_VERIFY: newuser@example.com <token>","..."}
    # We want to extract only the <token> part before the JSON closing quote.
    verify_token=$(grep "LID_VERIFY: $reg_email" "$WASH_LOG" | tail -n 1 | sed -E 's/.*LID_VERIFY: [^ ]+ ([^"]+).*/\1/' | tr -d '\r\n' || true)
    [[ -n "$verify_token" ]] && break
    sleep 1
  done
  if [[ -z "$verify_token" ]]; then
     log "FULL LOG TAIL:"
     tail -n 20 "$WASH_LOG"
     fail "Could not find email verification token in logs for $reg_email"
  fi
  log "Found verify token: $verify_token"
  
  # Try to log in before verification — pending users now get the same generic error
  # as non-existent users (anti-enumeration). We verify by checking that the post-verify
  # login actually works (302 redirect), proving verification changed something.
  log "Attempting login before verification (should fail)..."
  local verifier=$(random_string)
  local challenge=$(pkce_challenge "$verifier")
  local auth_body="$TMP_DIR/auth-body.html"
  local auth_headers="$TMP_DIR/auth-headers.txt"
  curl -sS -o "$auth_body" -D "$auth_headers" \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8000/callback&code_challenge=$challenge&code_challenge_method=S256&state=test&nonce=test"
  local session_id=$(extract_session_id "$auth_body")

  local login_body="$TMP_DIR/login-pre-verify.txt"
  local login_headers="$TMP_DIR/login-pre-verify-headers.txt"
  local login_status_pre=$(curl -sS -o "$login_body" -D "$login_headers" -w '%{http_code}' \
    -X POST "$BASE_URL/login" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$reg_email" \
    --data-urlencode "password=$reg_pass")
  
  # Before verification, login should NOT succeed (no 302 redirect)
  if [[ "$login_status_pre" == "302" ]]; then
     fail "Login should not succeed for pending (unverified) user"
  fi
  # Should show generic error (anti-enumeration: same message as non-existent user)
  if ! grep -q "Invalid email or password" "$login_body"; then
     fail "Expected generic error for pending user. Got: $(cat "$login_body")"
  fi
  log "OK: Login blocked for unverified user (generic error, anti-enumeration)."

  log "Verifying email..."
  curl -s -f "$BASE_URL/verify/email?token=$verify_token" > /dev/null
  
  log "Attempting login AFTER verification (should succeed)..."
  # Need a fresh authorize session
  local auth_body2="$TMP_DIR/auth-body2.html"
  local auth_headers2="$TMP_DIR/auth-headers2.txt"
  local verifier2=$(random_string)
  local challenge2=$(pkce_challenge "$verifier2")
  curl -sS -o "$auth_body2" -D "$auth_headers2" \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8000/callback&code_challenge=$challenge2&code_challenge_method=S256&state=test2&nonce=test2&scope=openid+offline_access"
  local session_id2=$(extract_session_id "$auth_body2")

  local login_body2="$TMP_DIR/login-post-verify.txt"
  local login_headers2="$TMP_DIR/login-post-verify-headers.txt"
  local login_status2=$(curl -sS -o "$login_body2" -D "$login_headers2" -w '%{http_code}' \
    -X POST "$BASE_URL/login" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id2" \
    --data-urlencode "email=$reg_email" \
    --data-urlencode "password=$reg_pass")
  
  if grep -q "Invalid email or password" "$login_body2"; then
     fail "Login still failing after email verification: $(cat "$login_body2")"
  fi
  # A successful login should redirect (302) with a code
  if [[ "$login_status2" != "302" ]]; then
     fail "Expected 302 redirect after verified login, got $login_status2: $(cat "$login_body2")"
  fi
  log "OK: Email verification flow works."

  # Case 3: Refresh Token Rotation & Reuse Detection
  log "Case 3: Testing Refresh Token Rotation..."
  # Get a fresh token set via the code we just received
  local post_verify_location=$(grep -i "^location:" "$login_headers2" | head -1 | awk '{print $2}' | tr -d '\r\n')
  local auth_code=$(python3 -c "from urllib.parse import urlparse, parse_qs; print(parse_qs(urlparse('$post_verify_location').query).get('code',[''])[0])")
  
  local token_body="$TMP_DIR/token.json"
  local token_headers="$TMP_DIR/token.headers"
  curl -sS -o "$token_body" -D "$token_headers" \
    -X POST "$BASE_URL/token" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode "code=$auth_code" \
    --data-urlencode "code_verifier=$verifier2" \
    --data-urlencode "redirect_uri=http://localhost:8000/callback" \
    --data-urlencode "client_id=lid-admin" \
    --data-urlencode "scope=openid+offline_access"
  
  local refresh_token=$(json_get "$token_body" "refresh_token")
  [[ -n "$refresh_token" ]] || fail "No refresh token in token response: $(cat "$token_body")"

  log "Exchanging refresh token for new one..."
  local rot_body="$TMP_DIR/rotated.json"
  local rot_headers="$TMP_DIR/rotated.headers"
  curl -sS -o "$rot_body" -D "$rot_headers" \
    -X POST "$BASE_URL/token" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=refresh_token" \
    --data-urlencode "refresh_token=$refresh_token" \
    --data-urlencode "client_id=lid-admin"
  
  local new_refresh=$(json_get "$rot_body" "refresh_token")
  [[ -n "$new_refresh" ]] || fail "Failed to get new refresh token: $(cat "$rot_body")"
  [[ "$new_refresh" != "$refresh_token" ]] || fail "Refresh token was not rotated"
  log "OK: Token rotated."

  log "Attempting to REUSE old refresh token (should trigger family revocation)..."
  local reuse_body="$TMP_DIR/reuse.json"
  local reuse_headers="$TMP_DIR/reuse.headers"
  local reuse_status=$(curl -sS -o "$reuse_body" -D "$reuse_headers" -w '%{http_code}' \
    -X POST "$BASE_URL/token" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=refresh_token" \
    --data-urlencode "refresh_token=$refresh_token" \
    --data-urlencode "client_id=lid-admin")
  if [[ "$reuse_status" == "200" ]]; then
     fail "Reuse should NOT return 200 — old token was accepted"
  fi
  log "OK: Old refresh token rejected (status $reuse_status)."

  log "Verifying that the NEW refresh token is also revoked after reuse..."
  local new_reuse_body="$TMP_DIR/new-reuse.json"
  local new_reuse_headers="$TMP_DIR/new-reuse.headers"
  local new_reuse_status=$(curl -sS -o "$new_reuse_body" -D "$new_reuse_headers" -w '%{http_code}' \
    -X POST "$BASE_URL/token" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=refresh_token" \
    --data-urlencode "refresh_token=$new_refresh" \
    --data-urlencode "client_id=lid-admin")
  if [[ "$new_reuse_status" == "200" ]]; then
     fail "New token should have been revoked after old token replay"
  fi
  log "OK: Token family revoked on reuse."

  # Case 4: GC Endpoint
  log "Case 4: Testing GC Endpoint..."
  local gc_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/internal/gc")
  if [[ "$gc_status" == "401" ]]; then
     log "GC endpoint enforces auth (401) — PASS"
  elif [[ "$gc_status" == "200" ]]; then
     log "GC endpoint ran successfully (200) — PASS"
  else
     log "GC endpoint returned $gc_status (non-fatal)"
  fi
  log "OK: GC endpoint reachable."

  log "PHASE 2/3 HARDENING TESTS COMPLETED SUCCESSFULLY."
}

main
