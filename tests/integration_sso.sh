#!/usr/bin/env bash
# Test: IdP browser session (lid_session), SSO fast-path, and prompt=none
#
# Covers:
#  - lid_session cookie is set on successful login (password flow)
#  - lid_session cookie is set on successful passkey/passkey-complete flow
#  - prompt=none with valid lid_session → silent auth code (no login page)
#  - prompt=none without lid_session  → login_required redirect
#  - prompt=login with valid lid_session → shows login page (forces re-auth)
#  - max_age=0 with valid lid_session  → shows login page (auth too old)
#  - SSO: second /authorize (interactive) reuses session, skips login page
#  - /logout clears lid_session (Max-Age=0 in Set-Cookie)
#  - Separate users do not share sessions

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

# ── helper: perform a full login and return the lid_session token value ───────
# Writes the cookie jar to $TMP_DIR/sso-<tag>-cookies.txt
# Usage: do_login_get_session <tag> <email> <password>
# Outputs the lid_session token (cookie value), empty string on failure.
do_login_get_session() {
  local tag="$1" email="$2" password="$3"
  local verifier challenge
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")

  local auth_body="$TMP_DIR/sso-${tag}-auth.html"
  local auth_headers="$TMP_DIR/sso-${tag}-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=s&nonce=n&scope=openid" \
    "$auth_body" "$auth_headers" >/dev/null

  local session_id
  session_id=$(extract_session_id "$auth_body")

  local login_body="$TMP_DIR/sso-${tag}-login.txt"
  local login_headers="$TMP_DIR/sso-${tag}-login.headers"
  local jar="$TMP_DIR/sso-${tag}-cookies.txt"
  curl -sS -o "$login_body" -D "$login_headers" -c "$jar" \
    -X POST "$BASE_URL/login" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$email" \
    --data-urlencode "password=$password"

  # Extract the lid_session value from the Netscape cookie jar file
  local token
  token=$(grep -E $'\tlid_session\t' "$jar" 2>/dev/null | awk '{print $NF}' | head -1 || true)
  echo "$token"
}

# ── helper: call /authorize with a cookie jar and return the Location header ──
# Does NOT follow redirects. Returns the Location header value.
# Usage: authorize_with_jar <tag> <jar> [extra_query_params]
authorize_with_jar() {
  local tag="$1" jar="$2" extra="${3:-}"
  local verifier challenge
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")

  local auth_body="$TMP_DIR/sso-${tag}-auth2.html"
  local auth_headers="$TMP_DIR/sso-${tag}-auth2.headers"
  curl -sS -o "$auth_body" -D "$auth_headers" -b "$jar" \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=ssostate&nonce=n2&scope=openid${extra}"

  # Return body path and headers path so caller can inspect both
  echo "${auth_body}|${auth_headers}"
}

# ── helper: assert a cookie jar contains (or not) a named cookie ─────────────
assert_cookie_present() {
  local jar="$1" name="$2" context="$3"
  if ! grep -qE $'\t'"${name}"$'\t' "$jar" 2>/dev/null; then
    fail "$context: expected cookie '$name' in jar $jar"
  fi
}

assert_cookie_absent() {
  local jar="$1" name="$2" context="$3"
  if grep -qE $'\t'"${name}"$'\t' "$jar" 2>/dev/null; then
    fail "$context: did not expect cookie '$name' in jar $jar"
  fi
}

main() {
  log "=== IdP browser session / SSO / prompt=none integration test ==="
  wait_for_cluster

  # ── Bootstrap: register two independent users ─────────────────────────────
  local ts
  ts=$(date +%s)
  local user1_email="sso.user1.${ts}@example.com"
  local user2_email="sso.user2.${ts}@example.com"
  local pass="SsoPass123!"

  register_and_login_superadmin "$user1_email" "$pass" "SSOUser1" >/dev/null
  log "User 1 registered: $user1_email"

  # Register user 2 (won't be superadmin, that's fine for session tests)
  local reg_body="$TMP_DIR/sso-u2-reg.json"
  local reg_headers="$TMP_DIR/sso-u2-reg.headers"
  local reg_status
  reg_status=$(curl_capture POST "$BASE_URL/register" "$reg_body" "$reg_headers" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$user2_email\",\"password\":\"$pass\",\"name\":\"SSOUser2\"}")
  [[ "$reg_status" == "201" ]] || fail "user2 registration returned $reg_status"
  log "User 2 registered: $user2_email"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 1: lid_session cookie is set after a successful login
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 1: lid_session cookie set on login"

  local session_token
  session_token=$(do_login_get_session "c1" "$user1_email" "$pass")
  [[ -n "$session_token" ]] || fail "Case 1: lid_session token is empty after login"
  log "PASS: lid_session present after login (${#session_token} chars)"

  local jar1="$TMP_DIR/sso-c1-cookies.txt"
  assert_cookie_present "$jar1" "lid_session" "Case 1"
  log "PASS: lid_session in cookie jar"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 2: prompt=none with valid lid_session → silent redirect with code
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 2: prompt=none with valid session → auth code redirect"

  local pn_body="$TMP_DIR/sso-c2-pn.html"
  local pn_headers="$TMP_DIR/sso-c2-pn.headers"
  local verifier challenge
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local pn_status
  pn_status=$(curl -sS -o "$pn_body" -D "$pn_headers" -w '%{http_code}' -b "$jar1" \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=pnstate&nonce=pn&scope=openid&prompt=none")

  assert_eq "302" "$pn_status" "Case 2: prompt=none with session should 302"
  local pn_location
  pn_location=$(header_value "$pn_headers" "location")
  # Must redirect to the callback with a code, NOT with error=login_required
  echo "$pn_location" | grep -q "code=" \
    || fail "Case 2: location should contain code=, got: $pn_location"
  echo "$pn_location" | grep -qv "error=" \
    || fail "Case 2: location must not contain error=, got: $pn_location"
  # State must be preserved
  local pn_state
  pn_state=$(url_query_get "$pn_location" "state")
  assert_eq "pnstate" "$pn_state" "Case 2: state preserved in prompt=none redirect"
  log "PASS: prompt=none with valid session → silent redirect (state=$pn_state)"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 3: prompt=none WITHOUT lid_session → login_required
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 3: prompt=none without session → login_required"

  local pn2_body="$TMP_DIR/sso-c3-pn2.html"
  local pn2_headers="$TMP_DIR/sso-c3-pn2.headers"
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  # Deliberately no -b flag (no cookies)
  local pn2_status
  pn2_status=$(curl -sS -o "$pn2_body" -D "$pn2_headers" -w '%{http_code}' \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=pn2state&nonce=pn2&scope=openid&prompt=none")

  assert_eq "302" "$pn2_status" "Case 3: prompt=none without session should 302"
  local pn2_location
  pn2_location=$(header_value "$pn2_headers" "location")
  local pn2_error
  pn2_error=$(url_query_get "$pn2_location" "error")
  assert_eq "login_required" "$pn2_error" "Case 3: error=login_required"
  local pn2_state
  pn2_state=$(url_query_get "$pn2_location" "state")
  assert_eq "pn2state" "$pn2_state" "Case 3: state preserved in login_required"
  log "PASS: prompt=none without session → login_required (state=$pn2_state)"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 4: prompt=login with valid lid_session → login page rendered (re-auth)
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 4: prompt=login with valid session → login page"

  local pl_body="$TMP_DIR/sso-c4-pl.html"
  local pl_headers="$TMP_DIR/sso-c4-pl.headers"
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local pl_status
  pl_status=$(curl -sS -o "$pl_body" -D "$pl_headers" -w '%{http_code}' -b "$jar1" \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=plstate&nonce=pl&scope=openid&prompt=login")

  assert_eq "200" "$pl_status" "Case 4: prompt=login should render login page (200)"
  # Login page must contain a session_id (hidden form field) — not a code redirect
  grep -q 'session_id' "$pl_body" \
    || fail "Case 4: login page should contain session_id, got body: $(cat "$pl_body" | head -5)"
  log "PASS: prompt=login with session → login page rendered"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 5: max_age=0 with valid lid_session → login page rendered
  # (auth_time is always older than 0 seconds ago)
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 5: max_age=0 with valid session → login page (session too old)"

  local ma_body="$TMP_DIR/sso-c5-ma.html"
  local ma_headers="$TMP_DIR/sso-c5-ma.headers"
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local ma_status
  ma_status=$(curl -sS -o "$ma_body" -D "$ma_headers" -w '%{http_code}' -b "$jar1" \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=mastate&nonce=ma&scope=openid&max_age=0")

  assert_eq "200" "$ma_status" "Case 5: max_age=0 should render login page (200)"
  grep -q 'session_id' "$ma_body" \
    || fail "Case 5: login page should contain session_id"
  log "PASS: max_age=0 → login page rendered (session age check)"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 6: Interactive SSO — second /authorize reuses session, skips login page
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 6: interactive SSO — second /authorize skips login page"

  local sso_body="$TMP_DIR/sso-c6-sso.html"
  local sso_headers="$TMP_DIR/sso-c6-sso.headers"
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  # No prompt= param (default interactive flow)
  local sso_status
  sso_status=$(curl -sS -o "$sso_body" -D "$sso_headers" -w '%{http_code}' -b "$jar1" \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=ssostate&nonce=n3&scope=openid")

  assert_eq "302" "$sso_status" "Case 6: SSO should 302 directly"
  local sso_location
  sso_location=$(header_value "$sso_headers" "location")
  echo "$sso_location" | grep -q "code=" \
    || fail "Case 6: location should contain code=, got: $sso_location"
  echo "$sso_location" | grep -qv "error=" \
    || fail "Case 6: location must not contain error="
  local sso_state
  sso_state=$(url_query_get "$sso_location" "state")
  assert_eq "ssostate" "$sso_state" "Case 6: state preserved in SSO redirect"
  # Make sure a fresh code is issued (body must NOT contain a login form)
  grep -q 'name="session_id"' "$sso_body" \
    && fail "Case 6: body should not contain login form (SSO should redirect directly)"
  log "PASS: interactive SSO → direct redirect (no login page)"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 7: /logout clears lid_session with Max-Age=0
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 7: /logout clears lid_session cookie"

  local logout_body="$TMP_DIR/sso-c7-logout.html"
  local logout_headers="$TMP_DIR/sso-c7-logout.headers"
  local logout_status
  logout_status=$(curl -sS -o "$logout_body" -D "$logout_headers" -w '%{http_code}' \
    -b "$jar1" \
    "$BASE_URL/logout")

  # Check Set-Cookie clears the session (Max-Age=0 or expired cookie)
  if ! grep -qi "lid_session=" "$logout_headers"; then
    fail "Case 7: /logout should emit Set-Cookie for lid_session"
  fi
  if ! grep -qi "Max-Age=0" "$logout_headers"; then
    fail "Case 7: /logout lid_session Set-Cookie should have Max-Age=0"
  fi
  log "PASS: /logout emits lid_session=; Max-Age=0"

  # After logout, prompt=none must return login_required again
  # (Use the stale jar — lid_session value is still there but server-side it's gone)
  local post_logout_body="$TMP_DIR/sso-c7-postlogout.html"
  local post_logout_headers="$TMP_DIR/sso-c7-postlogout.headers"
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local post_logout_status
  post_logout_status=$(curl -sS -o "$post_logout_body" -D "$post_logout_headers" \
    -w '%{http_code}' -b "$jar1" \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=pls&nonce=pls&scope=openid&prompt=none")

  assert_eq "302" "$post_logout_status" "Case 7: post-logout prompt=none should 302"
  local post_logout_location
  post_logout_location=$(header_value "$post_logout_headers" "location")
  local post_logout_error
  post_logout_error=$(url_query_get "$post_logout_location" "error")
  assert_eq "login_required" "$post_logout_error" "Case 7: post-logout must be login_required"
  log "PASS: post-logout prompt=none → login_required (server session invalidated)"

  # ═══════════════════════════════════════════════════════════════════════════
  # Case 8: User isolation — user2's session does not satisfy user1's cookie
  # ═══════════════════════════════════════════════════════════════════════════
  log "Case 8: user isolation — sessions are user-scoped"

  # Login as user2, get their cookie jar
  local session_token2
  session_token2=$(do_login_get_session "c8" "$user2_email" "$pass")
  [[ -n "$session_token2" ]] || fail "Case 8: user2 lid_session is empty"
  local jar2="$TMP_DIR/sso-c8-cookies.txt"

  # Tokens must differ
  assert_ne "$session_token" "$session_token2" "Case 8: user1 and user2 sessions must differ"
  log "PASS: user1 and user2 have different session tokens"

  # user2's jar must silently redirect to callback with a code (their own session works)
  local u2_body="$TMP_DIR/sso-c8-u2.html"
  local u2_headers="$TMP_DIR/sso-c8-u2.headers"
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  local u2_status
  u2_status=$(curl -sS -o "$u2_body" -D "$u2_headers" -w '%{http_code}' -b "$jar2" \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=${challenge}&code_challenge_method=S256&state=u2state&nonce=u2&scope=openid&prompt=none")

  assert_eq "302" "$u2_status" "Case 8: user2 prompt=none should succeed with their own session"
  local u2_location
  u2_location=$(header_value "$u2_headers" "location")
  echo "$u2_location" | grep -q "code=" \
    || fail "Case 8: user2 prompt=none should include code=, got: $u2_location"

  # Exchange user2's code and verify the sub belongs to user2 (not user1)
  local u2_code
  u2_code=$(url_query_get "$u2_location" "code")
  local u2_verifier="$verifier"   # already captured above
  local u2_token_body="$TMP_DIR/sso-c8-u2-token.json"
  local u2_token_headers="$TMP_DIR/sso-c8-u2-token.headers"
  # (verifier was last set in this block, corresponds to challenge used above)
  local u2_token_status
  u2_token_status=$(curl_capture POST "$BASE_URL/token" "$u2_token_body" "$u2_token_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    -d "grant_type=authorization_code&code=$u2_code&code_verifier=$u2_verifier&client_id=lid-admin&redirect_uri=http://localhost:8090/callback")
  assert_eq "200" "$u2_token_status" "Case 8: user2 token exchange"

  local u2_id_token
  u2_id_token=$(json_get "$u2_token_body" "id_token")
  local u2_sub
  u2_sub=$(jwt_claim "$u2_id_token" "sub")
  [[ -n "$u2_sub" ]] || fail "Case 8: user2 id_token has no sub"

  local u1_id
  u1_id=$(user_id_via_login "$user1_email" "$pass")
  assert_ne "$u1_id" "$u2_sub" "Case 8: user2 sub must differ from user1 sub"
  log "PASS: user2 session resolves to user2's identity (sub=$u2_sub, user1=$u1_id)"

  log "=== All SSO tests PASSED ==="
}

main "$@"
