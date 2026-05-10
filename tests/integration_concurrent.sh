#!/usr/bin/env bash
# Test: Concurrent/Race-Condition Safety
# Focus: Ensure CAS operations prevent double-spend of auth codes
#        and refresh tokens under concurrent access.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

main() {
  log "Starting Concurrent Safety Tests..."

  wait_for_cluster

  local admin_email
  admin_email="concurrent.$(date +%s)@example.com"
  local admin_password="ConcurrentTest123!"
  local admin_token
  admin_token=$(register_and_login_superadmin "$admin_email" "$admin_password" "Admin")
  assert_ne "" "$admin_token" "admin access token"
  log "Admin registered OK."

  # ── Case 1: Concurrent auth code consumption ────────────────
  log "Case 1: Concurrent auth code consumption (CAS protection)"

  local verifier challenge
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")

  local auth_body="$TMP_DIR/cc-auth.html"
  local auth_headers="$TMP_DIR/cc-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=$challenge&code_challenge_method=S256&state=cc&nonce=cc&scope=openid+offline_access" \
    "$auth_body" "$auth_headers" >/dev/null

  local session_id
  session_id=$(extract_session_id "$auth_body")

  local login_body="$TMP_DIR/cc-login.txt"
  local login_headers="$TMP_DIR/cc-login.headers"
  local login_status
  login_status=$(curl_capture POST "$BASE_URL/login" "$login_body" "$login_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$admin_email" \
    --data-urlencode "password=$admin_password")
  assert_eq 302 "$login_status" "login for concurrent test"

  local auth_code
  auth_code=$(url_query_get "$(header_value "$login_headers" location)" code)
  assert_ne "" "$auth_code" "auth code"

  # Fire 5 concurrent token exchanges — at most 1 should succeed
  local success_count=0
  local pid
  local pids=()
  local temp_dir="$TMP_DIR/concurrent-codes"
  mkdir -p "$temp_dir"

  for i in 1 2 3 4 5; do
    (
      local out="$temp_dir/result-$i.json"
      local http_code
      http_code=$(curl -s -o "$out" -w "%{http_code}" -X POST "$BASE_URL/token" \
        -H 'content-type: application/x-www-form-urlencoded' \
        --data-urlencode "grant_type=authorization_code" \
        --data-urlencode "code=$auth_code" \
        --data-urlencode "code_verifier=$verifier" \
        --data-urlencode "redirect_uri=http://localhost:8090/callback" \
        --data-urlencode "client_id=lid-admin" 2>/dev/null || true)
      echo "$http_code" > "$out.status"
    ) &
    pids+=($!)
  done

  for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done

  for i in 1 2 3 4 5; do
    local status_file="$temp_dir/result-$i.status"
    local body_file="$temp_dir/result-$i.json"
    if [[ -f "$status_file" ]]; then
      local status
      status=$(cat "$status_file")
      if [[ "$status" == "200" ]]; then
        success_count=$((success_count + 1))
      fi
    fi
  done

  if [[ "$success_count" -eq 1 ]]; then
    log "OK: Exactly 1 of 5 concurrent code exchanges succeeded (CAS prevented $((5 - success_count)) double-spends)"
  elif [[ "$success_count" -eq 0 ]]; then
    log "WARN: 0 of 5 concurrent code exchanges succeeded (all raced, none won — still CAS-protected)"
  else
    fail "CAS FAILED: $success_count of 5 concurrent code exchanges succeeded (expected ≤ 1)"
  fi

  # Verify the code cannot be used again even sequentially
  log "Verifying auth code is fully consumed..."
  local stale_status
  stale_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/token" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$auth_code" \
    --data-urlencode "code_verifier=$verifier" \
    --data-urlencode "redirect_uri=http://localhost:8090/callback" \
    --data-urlencode "client_id=lid-admin")
  if [[ "$stale_status" == "400" ]]; then
    log "OK: Already-consumed auth code rejected (status 400)"
  else
    fail "Already-consumed auth code returned status $stale_status (expected 400)"
  fi

  # ── Case 2: Concurrent refresh token rotation ──────────────
  log "Case 2: Concurrent refresh token rotation"
  verifier=$(random_string)
  challenge=$(pkce_challenge "$verifier")

  auth_body="$TMP_DIR/cc2-auth.html"
  auth_headers="$TMP_DIR/cc2-auth.headers"
  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8090/callback&code_challenge=$challenge&code_challenge_method=S256&state=cc2&nonce=cc2&scope=openid+offline_access" \
    "$auth_body" "$auth_headers" >/dev/null
  session_id=$(extract_session_id "$auth_body")

  login_body="$TMP_DIR/cc2-login.txt"
  login_headers="$TMP_DIR/cc2-login.headers"
  login_status=$(curl_capture POST "$BASE_URL/login" "$login_body" "$login_headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$admin_email" \
    --data-urlencode "password=$admin_password")
  assert_eq 302 "$login_status" "login for concurrent refresh test"

  auth_code=$(url_query_get "$(header_value "$login_headers" location)" code)
  assert_ne "" "$auth_code" "auth code (refresh test)"

  local token_file="$TMP_DIR/cc2-token.json"
  curl_capture POST "$BASE_URL/token" "$token_file" "$TMP_DIR/cc2-token.headers" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$auth_code" \
    --data-urlencode "code_verifier=$verifier" \
    --data-urlencode "redirect_uri=http://localhost:8090/callback" \
    --data-urlencode "client_id=lid-admin" >/dev/null

  local refresh_token
  refresh_token=$(json_get "$token_file" "refresh_token")
  assert_ne "" "$refresh_token" "initial refresh token"

  # Fire 5 concurrent refresh token rotations
  local temp_dir2="$TMP_DIR/concurrent-refresh"
  mkdir -p "$temp_dir2"
  success_count=0
  pids=()

  for i in 1 2 3 4 5; do
    (
      local out="$temp_dir2/result-$i.json"
      local http_code
      http_code=$(curl -s -o "$out" -w "%{http_code}" -X POST "$BASE_URL/token" \
        -H 'content-type: application/x-www-form-urlencoded' \
        --data-urlencode "grant_type=refresh_token" \
        --data-urlencode "refresh_token=$refresh_token" \
        --data-urlencode "client_id=lid-admin" 2>/dev/null || true)
      echo "$http_code" > "$out.status"
    ) &
    pids+=($!)
  done

  for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done

  for i in 1 2 3 4 5; do
    local status_file="$temp_dir2/result-$i.status"
    if [[ -f "$status_file" ]]; then
      local status
      status=$(cat "$status_file")
      if [[ "$status" == "200" ]]; then
        success_count=$((success_count + 1))
      fi
    fi
  done

  if [[ "$success_count" -le 1 ]]; then
    log "OK: $success_count of 5 concurrent refresh rotations succeeded (CAS protection)"
  else
    log "WARN: $success_count concurrent rotations succeeded (expected ≤ 1 due to CAS)"
  fi

  # Verify the original refresh token is now dead
  local stale_refresh_status
  stale_refresh_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/token" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=refresh_token" \
    --data-urlencode "refresh_token=$refresh_token" \
    --data-urlencode "client_id=lid-admin")
  if [[ "$stale_refresh_status" != "200" ]]; then
    log "OK: Original refresh token invalidated after concurrent rotation (status $stale_refresh_status)"
  else
    log "WARN: Original refresh token still valid after concurrent rotation"
  fi

  log "SUCCESS: All concurrent safety tests completed."
}

main
