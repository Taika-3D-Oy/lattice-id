#!/usr/bin/env bash
# Test: OIDC Protocol Negative Cases
# Focus: Ensure invalid requests, tokens, and scopes are correctly rejected

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

main() {
  log "Starting Protocol Negative Testing..."
  
  # Step 1: Start system & register admin
  start_wash_dev
  
  log "Registering admin..."
  local password="test-password-$(random_string)"
  local admin_token
  admin_token=$(register_and_login_superadmin "admin@example.com" "$password" "Admin")
  [[ -n "$admin_token" ]] || fail "Failed to get admin token"

  # Case 1: Invalid Bearer Token (Must fail)
  log "Case 1: Accessing protected resource with invalid token..."
  local status=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer invalid-garbage" "$BASE_URL/api/tenants")
  if [[ "$status" != "401" ]] && [[ "$status" != "400" ]]; then
    fail "Invalid token should return 401/400 (unauthorized), got $status"
  fi
  log "OK: Invalid token rejected."

  # Case 2: Expired/Malformed JWT (Simulated with garbage but correct header structure)
  log "Case 2: Malformed JWT structure..."
  local mal_status=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer a.b.c" "$BASE_URL/api/tenants")
  if [[ "$mal_status" == "200" ]]; then
    fail "Malformed JWT was accepted!"
  fi
  log "OK: Malformed JWT rejected."

  # Case 3: Missing required fields in POST
  log "Case 3: Empty JSON body..."
  local empty_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/api/tenants" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" -d "{}")
  if [[ "$empty_status" != "400" ]]; then
    fail "Empty JSON to create tenant should return 400, got $empty_status"
  fi
  log "OK: Invalid JSON body rejected."

  log "SUCCESS: All protocol negative cases passed."
}

main
