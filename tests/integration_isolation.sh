#!/usr/bin/env bash
# Test: Multi-tenant authorization isolation
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

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

wait_for_verify_token() {
  local email="$1"
  local token=""
  for _ in {1..30}; do
    token=$(python3 - "$WASH_LOG" "$email" <<'PY'
import re
import sys

log_path = sys.argv[1]
email = sys.argv[2]
pattern = re.compile(rf"LID_VERIFY:\s+{re.escape(email)}\s+(\w+)")
token = ""
with open(log_path, 'r', encoding='utf-8', errors='ignore') as handle:
    for line in handle:
        match = pattern.search(line)
        if match:
            token = match.group(1)
print(token)
PY
)
    if [[ -n "$token" ]]; then
      echo "$token"
      return 0
    fi
    sleep 1
  done
  fail "timed out waiting for verification token for $email"
}

verify_user_email() {
  local email="$1"
  local token
  token=$(wait_for_verify_token "$email")
  local body_file="$TMP_DIR/verify-$(echo "$email" | tr '@.' '__').html"
  local headers_file="$TMP_DIR/verify-$(echo "$email" | tr '@.' '__').headers"
  local status

  status=$(curl_capture GET "$BASE_URL/verify/email?token=$token" "$body_file" "$headers_file")
  assert_eq 200 "$status" "verify email $email"
}

user_id_by_email() {
  python3 - "$ROOT/dev-data/keyvalue/lid-user-idx" "$1" <<'PY'
import pathlib
import sys

bucket = pathlib.Path(sys.argv[1])
email = sys.argv[2].lower()
safe_key = f"email:{email}".replace(':', '--').replace('@', '_at_')
path = bucket / safe_key
if not path.exists():
    sys.stderr.write(f"user index entry not found for {email}\n")
    sys.exit(1)
print(path.read_text(encoding='utf-8'))
PY
}

add_user_to_tenant() {
  local admin_token="$1"
  local tenant_id="$2"
  local user_id="$3"
  local role="$4"
  local body_file="$TMP_DIR/add-$tenant_id-$user_id.json"
  local headers_file="$TMP_DIR/add-$tenant_id-$user_id.headers"
  local status

  status=$(curl_capture POST "$BASE_URL/api/tenants/$tenant_id/users" "$body_file" "$headers_file" \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer $admin_token" \
    -d "{\"user_id\":\"$user_id\",\"role\":\"$role\"}")
  assert_eq 201 "$status" "add user $user_id to tenant $tenant_id"
}

authorize_session() {
  local client_id="$1"
  local redirect_uri="$2"
  local code_challenge="$3"
  local state="$4"
  local body_file="$TMP_DIR/authorize-$state.html"
  local headers_file="$TMP_DIR/authorize-$state.headers"
  local status

  status=$(curl_capture GET "$BASE_URL/authorize?response_type=code&client_id=$client_id&redirect_uri=$redirect_uri&code_challenge=$code_challenge&code_challenge_method=S256&state=$state&nonce=$state" "$body_file" "$headers_file")
  assert_eq 200 "$status" "authorize page $state"
  extract_session_id "$body_file"
}

login_for_code() {
  local session_id="$1"
  local email="$2"
  local password="$3"
  local body_file="$TMP_DIR/login-$session_id.txt"
  local headers_file="$TMP_DIR/login-$session_id.headers"
  local status

  status=$(curl_capture POST "$BASE_URL/login" "$body_file" "$headers_file" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$email" \
    --data-urlencode "password=$password")
  assert_eq 302 "$status" "login redirect for $email"
  local location
  location=$(header_value "$headers_file" location) || fail "missing login redirect location for $email"
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

user_access_token() {
  local email="$1"
  local password="$2"
  local verifier
  verifier=$(random_string)
  local challenge
  challenge=$(pkce_challenge "$verifier")
  local session_id
  session_id=$(authorize_session 'lid-admin' 'http://localhost:8000/callback' "$challenge" "$(echo "$email" | tr '@.' '__')")
  local code
  code=$(login_for_code "$session_id" "$email" "$password")
  local body_file="$TMP_DIR/token-$(echo "$email" | tr '@.' '__').json"
  local headers_file="$TMP_DIR/token-$(echo "$email" | tr '@.' '__').headers"
  local status

  status=$(exchange_code "$code" "$verifier" 'http://localhost:8000/callback' 'lid-admin' "$body_file" "$headers_file")
  assert_eq 200 "$status" "token exchange for $email"
  json_get "$body_file" access_token
}

assert_forbidden() {
  local status="$1"
  local body_file="$2"
  local context="$3"
  if [[ "$status" == "200" ]]; then
    fail "$context unexpectedly succeeded"
  fi
  assert_contains_file 'forbidden' "$body_file" "$context"
}

main() {
  log "Starting multi-tenant isolation test..."
  start_wash_dev

  local admin_email="admin.$(date +%s)@example.com"
  local admin_password='changeme123'
  local admin_token
  admin_token=$(register_and_login_superadmin "$admin_email" "$admin_password" 'Isolation Admin')

  local tenant_a tenant_b
  tenant_a=$(create_tenant "$admin_token" 'tenant-a' 'Tenant A')
  tenant_b=$(create_tenant "$admin_token" 'tenant-b' 'Tenant B')

  local user_a_email="manager.a.$(date +%s)@example.com"
  local user_b_email="manager.b.$(date +%s)@example.com"
  local user_password='testpass123'

  register_user "$user_a_email" "$user_password" 'Tenant A Manager'
  register_user "$user_b_email" "$user_password" 'Tenant B Manager'
  verify_user_email "$user_a_email"
  verify_user_email "$user_b_email"

  local user_a_id user_b_id
  user_a_id=$(user_id_by_email "$user_a_email")
  user_b_id=$(user_id_by_email "$user_b_email")
  add_user_to_tenant "$admin_token" "$tenant_a" "$user_a_id" 'manager'
  add_user_to_tenant "$admin_token" "$tenant_b" "$user_b_id" 'manager'

  local token_a token_b
  token_a=$(user_access_token "$user_a_email" "$user_password")
  token_b=$(user_access_token "$user_b_email" "$user_password")

  assert_eq "$tenant_a" "$(jwt_claim "$token_a" tenant_id)" 'tenant A token tenant_id'
  assert_eq 'manager' "$(jwt_claim "$token_a" role)" 'tenant A token role'
  assert_eq "$tenant_b" "$(jwt_claim "$token_b" tenant_id)" 'tenant B token tenant_id'
  assert_eq 'manager' "$(jwt_claim "$token_b" role)" 'tenant B token role'

  local body_file headers_file status

  body_file="$TMP_DIR/tenant-a-users.json"
  headers_file="$TMP_DIR/tenant-a-users.headers"
  status=$(curl_capture GET "$BASE_URL/api/tenants/$tenant_a/users" "$body_file" "$headers_file" \
    -H "Authorization: Bearer $token_a")
  assert_eq 200 "$status" 'tenant A manager can list own tenant users'
  assert_contains_file "$user_a_email" "$body_file" 'tenant A user listing contains own user'

  body_file="$TMP_DIR/tenant-b-users-via-a.json"
  headers_file="$TMP_DIR/tenant-b-users-via-a.headers"
  status=$(curl_capture GET "$BASE_URL/api/tenants/$tenant_b/users" "$body_file" "$headers_file" \
    -H "Authorization: Bearer $token_a")
  assert_forbidden "$status" "$body_file" 'tenant A manager listing tenant B users'

  body_file="$TMP_DIR/tenant-a-users-via-b.json"
  headers_file="$TMP_DIR/tenant-a-users-via-b.headers"
  status=$(curl_capture GET "$BASE_URL/api/tenants/$tenant_a/users" "$body_file" "$headers_file" \
    -H "Authorization: Bearer $token_b")
  assert_forbidden "$status" "$body_file" 'tenant B manager listing tenant A users'

  body_file="$TMP_DIR/invite-cross-tenant.json"
  headers_file="$TMP_DIR/invite-cross-tenant.headers"
  status=$(curl_capture POST "$BASE_URL/api/tenants/$tenant_b/users/invite" "$body_file" "$headers_file" \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer $token_a" \
    -d '{"email":"cross-tenant@example.com","role":"member"}')
  assert_forbidden "$status" "$body_file" 'tenant A manager inviting into tenant B'

  body_file="$TMP_DIR/remove-cross-tenant.json"
  headers_file="$TMP_DIR/remove-cross-tenant.headers"
  status=$(curl_capture DELETE "$BASE_URL/api/tenants/$tenant_b/users/$user_b_id" "$body_file" "$headers_file" \
    -H "Authorization: Bearer $token_a")
  assert_forbidden "$status" "$body_file" 'tenant A manager removing tenant B user'

  body_file="$TMP_DIR/tenant-b-users.json"
  headers_file="$TMP_DIR/tenant-b-users.headers"
  status=$(curl_capture GET "$BASE_URL/api/tenants/$tenant_b/users" "$body_file" "$headers_file" \
    -H "Authorization: Bearer $token_b")
  assert_eq 200 "$status" 'tenant B manager can list own tenant users'
  assert_contains_file "$user_b_email" "$body_file" 'tenant B user listing contains own user'

  log "PASS: tenant managers are isolated to their own tenant resources"
}

main
