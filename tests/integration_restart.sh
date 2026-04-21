#!/usr/bin/env bash
# Test: Authority restart recovery and signing key continuity
# Focus: Ensure persisted keys and sessions survive a lattice-id workload restart
#
# This test verifies that:
#   1. Tokens issued before restart are valid after restart
#   2. JWKS keys survive restart (same kid)
#   3. Refresh tokens work across restarts
#   4. Management API remains accessible

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

authorize_session() {
  local client_id="$1"
  local redirect_uri="$2"
  local code_challenge="$3"
  local body_file="$TMP_DIR/restart-authorize.html"
  local headers_file="$TMP_DIR/restart-authorize.headers"
  local status

  status=$(curl_capture GET "$BASE_URL/authorize?response_type=code&client_id=$client_id&redirect_uri=$redirect_uri&code_challenge=$code_challenge&code_challenge_method=S256&scope=openid+email+profile+offline_access&state=restart-state&nonce=restart-nonce" "$body_file" "$headers_file")
  assert_eq 200 "$status" "authorize"
  extract_session_id "$body_file"
}

login_for_code() {
  local session_id="$1"
  local email="$2"
  local password="$3"
  local body_file="$TMP_DIR/restart-login-body.txt"
  local headers_file="$TMP_DIR/restart-login.headers"
  local status

  status=$(curl_capture POST "$BASE_URL/login" "$body_file" "$headers_file" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$email" \
    --data-urlencode "password=$password")
  assert_eq 302 "$status" "login"
  local location
  location=$(header_value "$headers_file" location) || fail "missing login redirect location"
  url_query_get "$location" code
}

exchange_code() {
  local code="$1"
  local verifier="$2"
  local redirect_uri="$3"
  local client_id="$4"
  local body_file="$5"
  local headers_file="$6"
  curl_capture POST "$BASE_URL/token" "$body_file" "$headers_file" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode "code=$code" \
    --data-urlencode "code_verifier=$verifier" \
    --data-urlencode "redirect_uri=$redirect_uri" \
    --data-urlencode "client_id=$client_id"
}

# Restart the lattice-id workload without wiping NATS (preserves data).
restart_lattice_id() {
  log "Restarting lattice-id workload..."
  local wd_name
  wd_name=$(kubectl ${KUBE_CTX_FLAG:-} get workloaddeployment ${KUBE_NS_FLAG:-} -o name 2>/dev/null \
    | grep "lattice-id" | head -1)
  if [[ -z "$wd_name" ]]; then
    fail "Cannot find lattice-id workload deployment"
  fi
  wd_name="${wd_name#workloaddeployment.runtime.wasmcloud.dev/}"

  # Save the manifest, delete, and re-apply
  kubectl ${KUBE_CTX_FLAG:-} get workloaddeployment "$wd_name" ${KUBE_NS_FLAG:-} -o yaml > "$TMP_DIR/lattice-id-wd.yaml"
  kubectl ${KUBE_CTX_FLAG:-} delete workloaddeployment "$wd_name" ${KUBE_NS_FLAG:-} --wait=true >/dev/null 2>&1
  sleep 5
  kubectl ${KUBE_CTX_FLAG:-} apply -f "$TMP_DIR/lattice-id-wd.yaml" >/dev/null 2>&1
  log "Workload re-applied, waiting for readiness..."

  # Wait for OIDC to come back up
  local attempts=0
  while true; do
    if curl -sf "$BASE_URL/.well-known/jwks.json" >/dev/null 2>&1; then
      break
    fi
    attempts=$((attempts + 1))
    if [[ $attempts -ge 120 ]]; then
      fail "Timed out waiting for cluster readiness after restart"
    fi
    sleep 1
  done
  log "Cluster ready after restart"
}

main() {
  log "Starting restart recovery test..."

  wait_for_cluster

  # Step 1: Register the admin (bootstrap hook promotes to superadmin)
  log "Registering admin (bootstrap hook will promote)..."
  local admin_email
  admin_email="restart.$(date +%s)@example.com"
  local secret="test-admin-password-$(random_string)"
  local admin_token
  admin_token=$(register_and_login_superadmin "$admin_email" "$secret" "Admin User")
  assert_ne "" "$admin_token" "admin access token"

  # Step 2: Issue a real OIDC token before restart
  log "Issuing pre-restart access token..."
  local verifier challenge session_id code token_body token_headers status access_token refresh_token kid
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")
  session_id=$(authorize_session 'lid-admin' 'http://localhost:8090/callback' "$challenge")
  code=$(login_for_code "$session_id" "$admin_email" "$secret")
  token_body="$TMP_DIR/restart-token.json"
  token_headers="$TMP_DIR/restart-token.headers"
  status=$(exchange_code "$code" "$verifier" 'http://localhost:8090/callback' 'lid-admin' "$token_body" "$token_headers")
  assert_eq 200 "$status" "pre-restart token exchange"
  access_token=$(json_get "$token_body" access_token)
  refresh_token=$(json_get "$token_body" refresh_token)
  kid=$(jwt_header_claim "$access_token" kid)
  assert_ne "" "$kid" "pre-restart token kid"

  local jwks_before_body="$TMP_DIR/jwks-before.json"
  local jwks_before_headers="$TMP_DIR/jwks-before.headers"
  status=$(curl_capture GET "$BASE_URL/.well-known/jwks.json" "$jwks_before_body" "$jwks_before_headers")
  assert_eq 200 "$status" "jwks before restart"
  assert_contains_file "$kid" "$jwks_before_body" "pre-restart JWKS contains token kid"

  local userinfo_before_body="$TMP_DIR/userinfo-before.json"
  local userinfo_before_headers="$TMP_DIR/userinfo-before.headers"
  status=$(curl_capture GET "$BASE_URL/userinfo" "$userinfo_before_body" "$userinfo_before_headers" \
    -H "Authorization: Bearer $access_token")
  assert_eq 200 "$status" "pre-restart userinfo"
  assert_eq "$admin_email" "$(json_get "$userinfo_before_body" email)" "pre-restart userinfo email"

  # Step 3: Verify the admin token has management access (proves superadmin)
  local tenants_body="$TMP_DIR/tenants-before.json"
  local tenants_headers="$TMP_DIR/tenants-before.headers"
  status=$(curl_capture GET "$BASE_URL/api/tenants" "$tenants_body" "$tenants_headers" \
    -H "Authorization: Bearer $admin_token")
  assert_eq 200 "$status" "management access before restart"

  # Step 4: Restart lattice-id workload (NATS + lattice-db data is preserved)
  restart_lattice_id

  # Step 5: Verify persistence and key continuity
  log "Verifying state after restart..."
  local tenants_after_body="$TMP_DIR/tenants-after.json"
  local tenants_after_headers="$TMP_DIR/tenants-after.headers"
  status=$(curl_capture GET "$BASE_URL/api/tenants" "$tenants_after_body" "$tenants_after_headers" \
    -H "Authorization: Bearer $admin_token")
  assert_eq 200 "$status" "management access after restart"

  local jwks_after_body="$TMP_DIR/jwks-after.json"
  local jwks_after_headers="$TMP_DIR/jwks-after.headers"
  status=$(curl_capture GET "$BASE_URL/.well-known/jwks.json" "$jwks_after_body" "$jwks_after_headers")
  assert_eq 200 "$status" "jwks after restart"
  assert_contains_file "$kid" "$jwks_after_body" "post-restart JWKS contains original token kid"

  local userinfo_after_body="$TMP_DIR/userinfo-after.json"
  local userinfo_after_headers="$TMP_DIR/userinfo-after.headers"
  status=$(curl_capture GET "$BASE_URL/userinfo" "$userinfo_after_body" "$userinfo_after_headers" \
    -H "Authorization: Bearer $access_token")
  assert_eq 200 "$status" "post-restart userinfo with pre-restart token"
  assert_eq "$admin_email" "$(json_get "$userinfo_after_body" email)" "post-restart userinfo email"

  local refresh_after_body="$TMP_DIR/refresh-after.json"
  local refresh_after_headers="$TMP_DIR/refresh-after.headers"
  status=$(curl_capture POST "$BASE_URL/token" "$refresh_after_body" "$refresh_after_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=refresh_token' \
    --data-urlencode "refresh_token=$refresh_token" \
    --data-urlencode 'client_id=lid-admin')
  assert_eq 200 "$status" "post-restart refresh with pre-restart refresh token"
  local new_access_token
  new_access_token=$(json_get "$refresh_after_body" access_token)
  assert_ne "" "$new_access_token" "post-restart refreshed access token"

  log "SUCCESS: Authority preserved bootstrap state, signing keys, and token validity across restart."
}

main
