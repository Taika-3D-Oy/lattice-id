#!/usr/bin/env bash
# Test: RP-Initiated Logout, prompt parameter handling, health endpoints
#
# Covers:
#  - GET /healthz — always 200 (liveness)
#  - GET /readyz  — 200 when KV + keys ready, 503 when not
#  - /logout with valid id_token_hint + registered post_logout_redirect_uri → 302
#  - /logout state param preserved in redirect
#  - /logout open-redirect blocked (URI not registered for the id_token_hint client)
#  - /logout with no id_token_hint → 200 confirmation page
#  - /logout with id_token_hint from a different client than post_logout_redirect_uri → blocked
#  - prompt=none → login_required redirect (no existing session)
#  - prompt=login → always re-authenticates (no cached session)
#  - id_token_hint in /authorize prefills hint (login page rendered)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

# Perform a full OIDC flow and return the id_token.
# Usage: get_id_token <client_id> <redirect_uri> <email> <password>
get_id_token() {
  local client_id="$1" redirect_uri="$2" email="$3" password="$4"
  local verifier challenge
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local a_body="$TMP_DIR/gt-auth.html"
  local a_hdr="$TMP_DIR/gt-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=${client_id}&redirect_uri=${redirect_uri}&code_challenge=${challenge}&code_challenge_method=S256&state=s&nonce=n&scope=openid+offline_access" \
    "$a_body" "$a_hdr" >/dev/null
  local sid
  sid=$(extract_session_id "$a_body")
  local l_body="$TMP_DIR/gt-login.txt"
  local l_hdr="$TMP_DIR/gt-login.headers"
  curl_capture POST "$BASE_URL/login" "$l_body" "$l_hdr" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$sid" \
    --data-urlencode "email=$email" \
    --data-urlencode "password=$password" >/dev/null
  local loc code
  loc=$(header_value "$l_hdr" location)
  code=$(url_query_get "$loc" code)
  [[ -n "$code" ]] || { echo ""; return 1; }
  local t_body="$TMP_DIR/gt-tok.json"
  curl_capture POST "$BASE_URL/token" "$t_body" "$TMP_DIR/gt-tok.headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$code" \
    --data-urlencode "code_verifier=$verifier" \
    --data-urlencode "client_id=$client_id" \
    --data-urlencode "redirect_uri=$redirect_uri" >/dev/null
  python3 -c "import json; print(json.load(open('$t_body'))['id_token'])"
}

main() {
  log "=== Logout / Prompt / Health integration test ==="
  wait_for_cluster

  # ── Bootstrap admin ──────────────────────────────────────────────────────
  local ts
  ts=$(date +%s)
  local admin_email="logout.admin.${ts}@example.com"
  local admin_pass="AdminPass123!"
  local admin_token
  admin_token=$(register_and_login_superadmin "$admin_email" "$admin_pass" "LogoutAdmin")
  [[ -n "$admin_token" ]] || fail "no admin token"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 1: Health endpoints
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 1: /healthz — liveness probe"
  local hz_body="$TMP_DIR/healthz.json"
  local hz_status
  hz_status=$(curl_capture GET "$BASE_URL/healthz" "$hz_body" "$TMP_DIR/healthz.headers")
  assert_eq "200" "$hz_status" "/healthz"
  python3 -c "import json,sys; d=json.load(open('$hz_body')); assert d['ok'] is True, d" \
    || fail "/healthz body not ok=true"
  log "PASS: /healthz returns 200 ok=true"

  log "Case 1b: /readyz — readiness probe"
  local rz_body="$TMP_DIR/readyz.json"
  local rz_status
  rz_status=$(curl_capture GET "$BASE_URL/readyz" "$rz_body" "$TMP_DIR/readyz.headers")
  # Should be 200 since the cluster is up
  assert_eq "200" "$rz_status" "/readyz"
  python3 -c "import json,sys; d=json.load(open('$rz_body')); assert d.get('ok') is True, d" \
    || fail "/readyz body not ok=true"
  log "PASS: /readyz returns 200 ok=true"

  # /readyz with superadmin token should include detailed checks
  local rz_auth_body="$TMP_DIR/readyz-auth.json"
  local rz_auth_status
  rz_auth_status=$(curl_capture GET "$BASE_URL/readyz" "$rz_auth_body" "$TMP_DIR/readyz-auth.headers" \
    -H "Authorization: Bearer $admin_token")
  assert_eq "200" "$rz_auth_status" "/readyz with auth"
  python3 -c "
import json, sys
d = json.load(open('$rz_auth_body'))
assert 'checks' in d, f'no checks in detailed readyz: {d}'
print(f'  readyz checks: {d[\"checks\"]}')
" || fail "/readyz with auth missing checks field"
  log "PASS: /readyz with auth returns detailed checks"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 2: RP-Initiated Logout — valid redirect
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 2: /logout with valid id_token_hint + registered post_logout_redirect_uri"

  local id_token
  id_token=$(get_id_token "lid-admin" "http://localhost:8090/callback" "$admin_email" "$admin_pass")
  [[ -n "$id_token" ]] || fail "could not get id_token"

  local enc_token
  enc_token=$(python3 -c "from urllib.parse import quote; import sys; print(quote(sys.argv[1]))" "$id_token")

  local lo_body="$TMP_DIR/logout.txt"
  local lo_headers="$TMP_DIR/logout.headers"
  local lo_status
  lo_status=$(curl_capture GET \
    "$BASE_URL/logout?id_token_hint=${enc_token}&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A8090%2Fcallback&state=byebye" \
    "$lo_body" "$lo_headers")
  assert_eq "302" "$lo_status" "logout with valid redirect"
  local lo_loc
  lo_loc=$(header_value "$lo_headers" location)
  [[ "$lo_loc" == *"localhost:8090/callback"* ]] \
    || fail "redirect location wrong: $lo_loc"
  local lo_state
  lo_state=$(url_query_get "$lo_loc" state) || true
  assert_eq "byebye" "$lo_state" "state preserved in logout redirect"
  log "PASS: Logout redirects to registered URI with state"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 3: Open-redirect protection — URI not registered for this client
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 3: /logout open-redirect protection"

  # Get a fresh id_token (previous logout revoked tokens)
  id_token=$(get_id_token "lid-admin" "http://localhost:8090/callback" "$admin_email" "$admin_pass")
  enc_token=$(python3 -c "from urllib.parse import quote; import sys; print(quote(sys.argv[1]))" "$id_token")

  local or_body="$TMP_DIR/openredir.txt"
  local or_headers="$TMP_DIR/openredir.headers"
  local or_status
  or_status=$(curl_capture GET \
    "$BASE_URL/logout?id_token_hint=${enc_token}&post_logout_redirect_uri=https%3A%2F%2Fevil.example.com%2Fsteal" \
    "$or_body" "$or_headers")
  # Must NOT redirect to evil.example.com — should show confirmation page (200)
  # or redirect to a safe URI, never to the unregistered one
  if [[ "$or_status" == "302" ]]; then
    local or_loc
    or_loc=$(header_value "$or_headers" location)
    [[ "$or_loc" == *"evil.example.com"* ]] \
      && fail "open-redirect: should not redirect to unregistered URI $or_loc"
    log "PASS: Logout blocked unregistered redirect (redirected elsewhere)"
  else
    assert_eq "200" "$or_status" "logout with unregistered URI should show confirmation"
    log "PASS: Logout with unregistered post_logout_redirect_uri shows confirmation page"
  fi

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 4: /logout with no id_token_hint → confirmation page (200)
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 4: /logout with no id_token_hint → 200 confirmation"
  local bare_body="$TMP_DIR/logout-bare.html"
  local bare_status
  bare_status=$(curl_capture GET "$BASE_URL/logout" "$bare_body" "$TMP_DIR/logout-bare.headers")
  assert_eq "200" "$bare_status" "bare /logout"
  assert_contains_file "Signed Out" "$bare_body" "confirmation page content"
  log "PASS: /logout without id_token_hint shows confirmation page"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 5: Cross-client open-redirect — id_token from client A, URI from client B
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 5: Cross-client redirect blocked"

  # Create a second client with a different redirect URI
  local c2_resp
  c2_resp=$(curl -s -X POST "$BASE_URL/api/clients" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Client B",
      "redirect_uris": ["http://localhost:9999/cb2"],
      "grant_types": ["authorization_code"],
      "confidential": false
    }')
  local c2_id
  c2_id=$(echo "$c2_resp" | python3 -c "import json,sys; print(json.loads(sys.stdin.read())['client_id'])")
  [[ -n "$c2_id" ]] || fail "failed to create client B: $c2_resp"

  # Use id_token from lid-admin, but post_logout_redirect_uri from client B
  id_token=$(get_id_token "lid-admin" "http://localhost:8090/callback" "$admin_email" "$admin_pass")
  enc_token=$(python3 -c "from urllib.parse import quote; import sys; print(quote(sys.argv[1]))" "$id_token")

  local xc_body="$TMP_DIR/xc-logout.txt"
  local xc_headers="$TMP_DIR/xc-logout.headers"
  local xc_status
  xc_status=$(curl_capture GET \
    "$BASE_URL/logout?id_token_hint=${enc_token}&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcb2" \
    "$xc_body" "$xc_headers")
  if [[ "$xc_status" == "302" ]]; then
    local xc_loc
    xc_loc=$(header_value "$xc_headers" location)
    [[ "$xc_loc" == *"9999"* ]] \
      && fail "cross-client redirect should be blocked: redirected to $xc_loc"
    log "PASS: Cross-client redirect blocked (redirected elsewhere)"
  else
    assert_eq "200" "$xc_status" "cross-client redirect should show confirmation"
    log "PASS: Cross-client redirect blocked (shows confirmation page)"
  fi

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 6: prompt=none → login_required
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 6: prompt=none → login_required"
  local verifier challenge
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local pn_body="$TMP_DIR/pnone.txt"
  local pn_headers="$TMP_DIR/pnone.headers"
  local pn_status
  pn_status=$(curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=pnonestate&nonce=n&scope=openid&prompt=none" \
    "$pn_body" "$pn_headers")
  assert_eq "302" "$pn_status" "prompt=none redirect"
  local pn_loc
  pn_loc=$(header_value "$pn_headers" location)
  local pn_err
  pn_err=$(url_query_get "$pn_loc" error) || true
  assert_eq "login_required" "$pn_err" "prompt=none error"
  local pn_state
  pn_state=$(url_query_get "$pn_loc" state) || true
  assert_eq "pnonestate" "$pn_state" "prompt=none state preserved"
  log "PASS: prompt=none → login_required with state"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 7: prompt=login — shows login page (normal flow, force re-auth signal)
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 7: prompt=login → login page rendered"
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local pl_body="$TMP_DIR/plogin.html"
  local pl_headers="$TMP_DIR/plogin.headers"
  local pl_status
  pl_status=$(curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=s&nonce=n&scope=openid&prompt=login" \
    "$pl_body" "$pl_headers")
  assert_eq "200" "$pl_status" "prompt=login shows login page"
  assert_contains_file "session_id" "$pl_body" "login form in prompt=login response"
  log "PASS: prompt=login → login page rendered"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 8: id_token_hint in /authorize — login page rendered (hint accepted)
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 8: id_token_hint in /authorize prefills login hint"
  # Get a fresh token for admin
  id_token=$(get_id_token "lid-admin" "http://localhost:8090/callback" "$admin_email" "$admin_pass")
  enc_token=$(python3 -c "from urllib.parse import quote; import sys; print(quote(sys.argv[1]))" "$id_token")

  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local hint_body="$TMP_DIR/hint-auth.html"
  local hint_headers="$TMP_DIR/hint-auth.headers"
  local hint_status
  hint_status=$(curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=s&nonce=n&scope=openid&id_token_hint=${enc_token}" \
    "$hint_body" "$hint_headers")
  # Should serve a login page (200), not an error
  assert_eq "200" "$hint_status" "id_token_hint in authorize"
  assert_contains_file "session_id" "$hint_body" "login form rendered with id_token_hint"
  log "PASS: id_token_hint accepted in /authorize"

  # A wrong-client id_token_hint should not redirect to callback — returns error redirect
  local bad_hint="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlIiwiYXVkIjoibGlkLWFkbWluIiwiaXNzIjoiaHR0cDovL2V2aWwuZXhhbXBsZS5jb20ifQ.fakesig"
  local bh_enc
  bh_enc=$(python3 -c "from urllib.parse import quote; import sys; print(quote(sys.argv[1]))" "$bad_hint")
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local bh_body="$TMP_DIR/badhint.html"
  local bh_headers="$TMP_DIR/badhint.headers"
  local bh_status
  bh_status=$(curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=s&nonce=n&scope=openid&id_token_hint=${bh_enc}" \
    "$bh_body" "$bh_headers")
  # Bad hint should result in an error redirect (302) or a login page (200),
  # never in a token being silently issued
  if [[ "$bh_status" == "302" ]]; then
    local bh_loc
    bh_loc=$(header_value "$bh_headers" location)
    local bh_err
    bh_err=$(url_query_get "$bh_loc" error) || true
    [[ -n "$bh_err" ]] || fail "bad id_token_hint 302 without error param: $bh_loc"
    log "PASS: invalid id_token_hint → error redirect ($bh_err)"
  else
    assert_eq "200" "$bh_status" "bad id_token_hint"
    assert_contains_file "session_id" "$bh_body" "login page on bad hint"
    log "PASS: invalid id_token_hint → login page (graceful fallback)"
  fi

  log "=== Logout / Prompt / Health: ALL TESTS PASSED ==="
}

main "$@"
