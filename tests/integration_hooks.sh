#!/usr/bin/env bash
# Test: Rhai scripting hooks — post-login and post-registration Actions
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

# ── Helpers ──────────────────────────────────────────────────

create_tenant() {
  local admin_token="$1"
  local name="$2"
  local display_name="$3"
  local body_file="$TMP_DIR/tenant-$name.json"
  local headers_file="$TMP_DIR/tenant-$name.headers"
  local status

  status=$(curl_capture POST "$BASE_URL/api/tenants" "$body_file" "$headers_file" \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer $admin_token" \
    -d "{\"name\":\"$name\",\"display_name\":\"$display_name\"}")
  assert_eq 201 "$status" "create tenant $name"
  json_get "$body_file" id
}

register_user() {
  local email="$1"
  local password="$2"
  local name="$3"
  local body_file="$TMP_DIR/register-$(echo "$email" | tr '@.' '__').json"
  local headers_file="$TMP_DIR/register-$(echo "$email" | tr '@.' '__').headers"
  local status

  status=$(curl_capture POST "$BASE_URL/register" "$body_file" "$headers_file" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$email\",\"password\":\"$password\",\"name\":\"$name\"}")
  assert_eq 201 "$status" "register $email"
}

verify_user_email() {
  log "Skipping email verification for $1 (cluster mode)"
}

authorize_session() {
  local client_id="$1"
  local redirect_uri="$2"
  local code_challenge="$3"
  local body_file="$TMP_DIR/authorize.html"
  local headers_file="$TMP_DIR/authorize.headers"

  curl_capture GET \
    "$BASE_URL/authorize?response_type=code&client_id=$client_id&redirect_uri=$redirect_uri&scope=openid+email+profile&state=test&nonce=test-nonce&code_challenge=$code_challenge&code_challenge_method=S256" \
    "$body_file" "$headers_file" >/dev/null

  extract_session_id "$body_file"
}

login_for_code() {
  local session_id="$1"
  local email="$2"
  local password="$3"
  local redirect_uri="$4"
  local body_file="$TMP_DIR/login-$(echo "$email" | tr '@.' '__').html"
  local headers_file="$TMP_DIR/login-$(echo "$email" | tr '@.' '__').headers"
  local status

  status=$(curl_capture POST "$BASE_URL/login" "$body_file" "$headers_file" \
    -H 'content-type: application/x-www-form-urlencoded' \
    -d "session_id=$session_id&email=$email&password=$password")
  assert_eq 302 "$status" "login $email"

  local location
  location=$(header_value "$headers_file" "location")
  url_query_get "$location" "code"
}

exchange_code_for_tokens() {
  local code="$1"
  local code_verifier="$2"
  local client_id="$3"
  local redirect_uri="$4"
  local body_file="$TMP_DIR/token.json"
  local headers_file="$TMP_DIR/token.headers"
  local status

  status=$(curl_capture POST "$BASE_URL/token" "$body_file" "$headers_file" \
    -H 'content-type: application/x-www-form-urlencoded' \
    -d "grant_type=authorization_code&code=$code&code_verifier=$code_verifier&client_id=$client_id&redirect_uri=$redirect_uri")
  assert_eq 200 "$status" "token exchange"

  json_get "$body_file" "access_token"
}

# ── Start lattice ────────────────────────────────────────────

wait_for_cluster

log "=== Test: Rhai scripting hooks ==="

# Generate unique emails per run to avoid collisions
TS="$(date +%s)"
PROMOTE_EMAIL="promote.${TS}@hooks-test.com"
REGULAR_EMAIL="regular.${TS}@hooks-test.com"

# ── Setup: register first user (bootstrap hook promotes to superadmin) ──

ADMIN_TOKEN=$(register_and_login_superadmin "admin.${TS}@hooks-test.com" "password123" "Hook Admin")
log "Admin registered and promoted via bootstrap hook"

# Create a tenant for auto-join tests
TENANT_ID=$(create_tenant "$ADMIN_TOKEN" "auto-org" "Auto Organization")
log "Created tenant: $TENANT_ID"

# ── Test 1: List hooks (should be empty) ─────────────────────

log "Test 1: List hooks (empty)"
HOOKS_BODY="$TMP_DIR/hooks-list.json"
HOOKS_HEADERS="$TMP_DIR/hooks-list.headers"
STATUS=$(curl_capture GET "$BASE_URL/api/hooks" "$HOOKS_BODY" "$HOOKS_HEADERS" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
assert_eq 200 "$STATUS" "list hooks"
HOOKS_COUNT=$(python3 -c "import json; print(len(json.load(open('$HOOKS_BODY'))))")
assert_eq 0 "$HOOKS_COUNT" "initial hooks count"
log "PASS: no hooks initially"

# ── Test 2: Create a post-login hook (superadmin promotion) ──

log "Test 2: Create post-login hook"
HOOK_SCRIPT="if user.email == \"$PROMOTE_EMAIL\" { set_superadmin(true); log(\"promoted to superadmin\"); }"
HOOK_BODY="$TMP_DIR/hook-create.json"
HOOK_HEADERS="$TMP_DIR/hook-create.headers"
HOOK_PAYLOAD=$(python3 -c "import json,sys; print(json.dumps({'name':'Auto Promote','trigger':'post-login','script':sys.argv[1],'priority':0}))" "$HOOK_SCRIPT")
STATUS=$(curl_capture POST "$BASE_URL/api/hooks" "$HOOK_BODY" "$HOOK_HEADERS" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d "$HOOK_PAYLOAD")
assert_eq 201 "$STATUS" "create hook"
HOOK_ID=$(json_get "$HOOK_BODY" id)
HOOK_VERSION=$(json_get "$HOOK_BODY" version)
HOOK_HASH=$(json_get "$HOOK_BODY" script_hash)
assert_eq 1 "$HOOK_VERSION" "initial hook version should be 1"
assert_ne "" "$HOOK_HASH" "hook should have a script_hash"
log "Created hook: $HOOK_ID (v$HOOK_VERSION, hash=$HOOK_HASH)"

# ── Test 3: List hooks (should have 1) ───────────────────────

log "Test 3: Verify hook exists"
STATUS=$(curl_capture GET "$BASE_URL/api/hooks" "$HOOKS_BODY" "$HOOKS_HEADERS" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
assert_eq 200 "$STATUS" "list hooks after create"
HOOKS_COUNT=$(python3 -c "import json; print(len(json.load(open('$HOOKS_BODY'))))")
assert_eq 1 "$HOOKS_COUNT" "hooks count after create"
log "PASS: 1 hook exists"

# ── Test 4: Test hook dry-run ─────────────────────────────────

log "Test 4: Dry-run hook"
TEST_BODY="$TMP_DIR/hook-test.json"
TEST_HEADERS="$TMP_DIR/hook-test.headers"
STATUS=$(curl_capture POST "$BASE_URL/api/hooks/$HOOK_ID/test" "$TEST_BODY" "$TEST_HEADERS" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
assert_eq 200 "$STATUS" "test hook"
TEST_SUCCESS=$(json_get "$TEST_BODY" success)
assert_eq "true" "$TEST_SUCCESS" "hook test success"
log "PASS: hook dry-run succeeded"

# ── Test 5: Create post-login hook with set_claim ────────────

log "Test 5: Create hook with custom claims"
CLAIM_SCRIPT="if user.email == \"$PROMOTE_EMAIL\" { set_claim(\"department\", \"engineering\"); }"
CLAIM_PAYLOAD=$(python3 -c "import json,sys; print(json.dumps({'name':'Add Department Claim','trigger':'post-login','script':sys.argv[1],'priority':10}))" "$CLAIM_SCRIPT")
STATUS=$(curl_capture POST "$BASE_URL/api/hooks" "$HOOK_BODY" "$HOOK_HEADERS" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d "$CLAIM_PAYLOAD")
assert_eq 201 "$STATUS" "create claim hook"
CLAIM_HOOK_ID=$(json_get "$HOOK_BODY" id)
log "Created claim hook: $CLAIM_HOOK_ID"

# ── Test 6: Register user, verify, and login to trigger hooks ──

log "Test 6: Register and login to trigger post-login hooks"
register_user "$PROMOTE_EMAIL" "password123" "Promo User"
verify_user_email "$PROMOTE_EMAIL"

CLIENT_ID="lid-admin"
REDIRECT_URI="http://localhost:8090/callback"
CODE_VERIFIER=$(random_string)
CODE_CHALLENGE=$(pkce_challenge "$CODE_VERIFIER")

SESSION_ID=$(authorize_session "$CLIENT_ID" "$REDIRECT_URI" "$CODE_CHALLENGE")
AUTH_CODE=$(login_for_code "$SESSION_ID" "$PROMOTE_EMAIL" "password123" "$REDIRECT_URI")
ACCESS_TOKEN=$(exchange_code_for_tokens "$AUTH_CODE" "$CODE_VERIFIER" "$CLIENT_ID" "$REDIRECT_URI")

# Verify the superadmin promotion took effect
ROLE=$(jwt_claim "$ACCESS_TOKEN" "role")
assert_eq "superadmin" "$ROLE" "user should be superadmin after hook"
log "PASS: user promoted to superadmin by post-login hook"

# Verify the custom claim was injected
DEPT=$(jwt_claim "$ACCESS_TOKEN" "department")
assert_eq "engineering" "$DEPT" "custom claim from set_claim() hook"
log "PASS: custom claim 'department=engineering' injected by hook"

# ── Test 7: Non-matching user doesn't get promoted ───────────

log "Test 7: Non-matching user unaffected"
register_user "$REGULAR_EMAIL" "password123" "Regular User"
verify_user_email "$REGULAR_EMAIL"

CODE_VERIFIER2=$(random_string)
CODE_CHALLENGE2=$(pkce_challenge "$CODE_VERIFIER2")
SESSION_ID2=$(authorize_session "$CLIENT_ID" "$REDIRECT_URI" "$CODE_CHALLENGE2")
AUTH_CODE2=$(login_for_code "$SESSION_ID2" "$REGULAR_EMAIL" "password123" "$REDIRECT_URI")
ACCESS_TOKEN2=$(exchange_code_for_tokens "$AUTH_CODE2" "$CODE_VERIFIER2" "$CLIENT_ID" "$REDIRECT_URI")

ROLE2=$(jwt_claim "$ACCESS_TOKEN2" "role")
assert_ne "superadmin" "$ROLE2" "regular user should NOT be superadmin"
log "PASS: non-matching user is NOT promoted"

# ── Test 8: Update hook ──────────────────────────────────────

log "Test 8: Update hook"
UPDATE_BODY="$TMP_DIR/hook-update.json"
UPDATE_HEADERS="$TMP_DIR/hook-update.headers"
STATUS=$(curl_capture PUT "$BASE_URL/api/hooks/$HOOK_ID" "$UPDATE_BODY" "$UPDATE_HEADERS" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"enabled":false}')
assert_eq 200 "$STATUS" "update hook"
ENABLED=$(json_get "$UPDATE_BODY" enabled)
assert_eq "false" "$ENABLED" "hook should be disabled"
UPDATED_VERSION=$(json_get "$UPDATE_BODY" version)
assert_eq 2 "$UPDATED_VERSION" "version should increment to 2 on update"
log "PASS: hook disabled via update (v$UPDATED_VERSION)"

# ── Test 8b: Version history ─────────────────────────────────

log "Test 8b: Version history for hook"
VER_BODY="$TMP_DIR/hook-versions.json"
VER_HEADERS="$TMP_DIR/hook-versions.headers"
STATUS=$(curl_capture GET "$BASE_URL/api/hooks/$HOOK_ID/versions" "$VER_BODY" "$VER_HEADERS" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
assert_eq 200 "$STATUS" "list hook versions"
VER_COUNT=$(python3 -c "import json; print(len(json.load(open('$VER_BODY'))))")
assert_eq 2 "$VER_COUNT" "should have 2 versions (create + update)"
VER1=$(python3 -c "import json; d=json.load(open('$VER_BODY')); print(d[0]['version'])")
VER2=$(python3 -c "import json; d=json.load(open('$VER_BODY')); print(d[1]['version'])")
assert_eq 1 "$VER1" "first version should be 1"
assert_eq 2 "$VER2" "second version should be 2"
# Each version has script content for diff
V1_HASH=$(python3 -c "import json; d=json.load(open('$VER_BODY')); print(d[0]['script_hash'])")
V2_HASH=$(python3 -c "import json; d=json.load(open('$VER_BODY')); print(d[1]['script_hash'])")
assert_eq "$HOOK_HASH" "$V1_HASH" "version 1 hash should match original"
# V2 hash is same script (only enabled changed), so hash should be same
assert_eq "$V1_HASH" "$V2_HASH" "hash should be same when only enabled changed"
# Each version records who changed it
V2_CHANGED_BY=$(python3 -c "import json; d=json.load(open('$VER_BODY')); print(d[1]['changed_by'])")
assert_ne "" "$V2_CHANGED_BY" "version should record who changed it"
log "PASS: version history has 2 entries with full script + metadata"

# ── Test 9: Delete hook ──────────────────────────────────────

log "Test 9: Delete hook"
DELETE_BODY="$TMP_DIR/hook-delete.json"
DELETE_HEADERS="$TMP_DIR/hook-delete.headers"
STATUS=$(curl_capture DELETE "$BASE_URL/api/hooks/$CLAIM_HOOK_ID" "$DELETE_BODY" "$DELETE_HEADERS" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
assert_eq 200 "$STATUS" "delete hook"
log "PASS: hook deleted"

# Verify only 1 hook remains (the disabled one)
STATUS=$(curl_capture GET "$BASE_URL/api/hooks" "$HOOKS_BODY" "$HOOKS_HEADERS" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
HOOKS_COUNT=$(python3 -c "import json; print(len(json.load(open('$HOOKS_BODY'))))")
assert_eq 1 "$HOOKS_COUNT" "hooks count after delete"

# ── Test 10: Hook with invalid script rejected ───────────────

log "Test 10: Invalid script rejected"
BAD_BODY="$TMP_DIR/hook-bad.json"
BAD_HEADERS="$TMP_DIR/hook-bad.headers"
STATUS=$(curl_capture POST "$BASE_URL/api/hooks" "$BAD_BODY" "$BAD_HEADERS" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"Bad Hook","trigger":"post-login","script":"this is not valid }{{"}')
assert_eq 400 "$STATUS" "invalid script should be rejected"
log "PASS: invalid Rhai script rejected at creation"

# ── Test 11: Non-superadmin cannot manage hooks ──────────────

log "Test 11: Non-superadmin cannot manage hooks"
# Get a non-superadmin token (the regular user)
CODE_VERIFIER3=$(random_string)
CODE_CHALLENGE3=$(pkce_challenge "$CODE_VERIFIER3")
SESSION_ID3=$(authorize_session "$CLIENT_ID" "$REDIRECT_URI" "$CODE_CHALLENGE3")
AUTH_CODE3=$(login_for_code "$SESSION_ID3" "$REGULAR_EMAIL" "password123" "$REDIRECT_URI")
REGULAR_TOKEN=$(exchange_code_for_tokens "$AUTH_CODE3" "$CODE_VERIFIER3" "$CLIENT_ID" "$REDIRECT_URI")

UNAUTH_BODY="$TMP_DIR/hooks-unauth.json"
UNAUTH_HEADERS="$TMP_DIR/hooks-unauth.headers"
STATUS=$(curl_capture GET "$BASE_URL/api/hooks" "$UNAUTH_BODY" "$UNAUTH_HEADERS" \
  -H "Authorization: Bearer $REGULAR_TOKEN")
assert_ne 200 "$STATUS" "non-superadmin should be forbidden from hooks API"
log "PASS: non-superadmin denied access to hooks API"

# ── Done ─────────────────────────────────────────────────────

log "=== All hooks tests passed! ==="
