#!/usr/bin/env bash
# Test: Full Authority Flow (Bootstrap -> Login -> Session)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

assert_eq() {
  local expected="$1"
  local actual="$2"
  local context="$3"
  if [[ "$expected" != "$actual" ]]; then
    fail "$context: expected '$expected', got '$actual'"
  fi
}

assert_ne() {
  local left="$1"
  local right="$2"
  local context="$3"
  if [[ "$left" == "$right" ]]; then
    fail "$context: values should differ but both were '$left'"
  fi
}

assert_matches() {
  local value="$1"
  local pattern="$2"
  local context="$3"
  if [[ ! "$value" =~ $pattern ]]; then
    fail "$context: value '$value' did not match /$pattern/"
  fi
}

assert_int_delta_le() {
  local left="$1"
  local right="$2"
  local maximum="$3"
  local context="$4"
  python3 - "$left" "$right" "$maximum" "$context" <<'PY'
import sys

left = int(sys.argv[1])
right = int(sys.argv[2])
maximum = int(sys.argv[3])
context = sys.argv[4]
if abs(left - right) > maximum:
    sys.stderr.write(f"{context}: expected |{left} - {right}| <= {maximum}\n")
    sys.exit(1)
PY
}

jwt_claim_optional() {
  python3 - "$1" "$2" <<'PY'
import base64
import json
import sys

token = sys.argv[1]
path = sys.argv[2].split('.')
parts = token.split('.')
if len(parts) != 3:
  sys.stderr.write('invalid JWT format\n')
  sys.exit(1)

payload = parts[1]
payload += '=' * (-len(payload) % 4)
value = json.loads(base64.urlsafe_b64decode(payload.encode('ascii')))

try:
  for part in path:
    if not part:
      continue
    if isinstance(value, list):
      value = value[int(part)]
    else:
      value = value[part]
except Exception:
  print('')
  sys.exit(0)

if isinstance(value, bool):
  print('true' if value else 'false')
elif value is None:
  print('')
else:
  print(value)
PY
}

assert_metric_ge() {
  local file="$1"
  local metric_name="$2"
  local selector="$3"
  local minimum="$4"
  local context="$5"
  local value
  value=$(prometheus_metric_value "$file" "$metric_name" "$selector")
  python3 - "$value" "$minimum" "$context" <<'PY'
import sys

value = float(sys.argv[1])
minimum = float(sys.argv[2])
context = sys.argv[3]
if value < minimum:
    sys.stderr.write(f"{context}: expected >= {minimum}, got {value}\n")
    sys.exit(1)
PY
}

assert_contains_file() {
  local needle="$1"
  local file="$2"
  local context="$3"
  if ! grep -Fq "$needle" "$file"; then
    fail "$context: expected '$needle' in $(basename "$file")"
  fi
}

curl_capture() {
  local method="$1"
  local url="$2"
  local body_file="$3"
  local headers_file="$4"
  shift 4
  curl -sS -o "$body_file" -D "$headers_file" -w '%{http_code}' -X "$method" "$url" "$@"
}

create_client() {
  local admin_token="$1"
  local name="$2"
  local redirect_uri="$3"
  local confidential="${4:-false}"
  local body_file="$TMP_DIR/client-body.json"
  local headers_file="$TMP_DIR/client-headers.txt"
  local status

  status=$(curl_capture POST "$BASE_URL/api/clients" "$body_file" "$headers_file" \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer $admin_token" \
    -d "{\"name\":\"$name\",\"redirect_uris\":[\"$redirect_uri\"],\"confidential\":$confidential}")
  assert_eq 201 "$status" "client creation"
  local client_secret
  client_secret=$(python3 - "$body_file" <<'PY'
import json
import sys

with open(sys.argv[1], 'r', encoding='utf-8') as handle:
    value = json.load(handle)
print(value.get('client_secret', ''))
PY
)
  echo "$(json_get "$body_file" client_id)|$client_secret"
}

introspect_token() {
  local token="$1"
  local client_id="$2"
  local client_secret="$3"
  local body_file="$4"
  local headers_file="$5"
  curl_capture POST "$BASE_URL/token/introspect" "$body_file" "$headers_file" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "token=$token" \
    --data-urlencode "client_id=$client_id" \
    --data-urlencode "client_secret=$client_secret"
}

query_audit() {
  local token="$1"
  local url="$2"
  local body_file="$3"
  local headers_file="$4"
  curl_capture GET "$url" "$body_file" "$headers_file" \
    -H "Authorization: Bearer $token"
}

authorize_session() {
  local client_id="$1"
  local redirect_uri="$2"
  local code_challenge="$3"
  local extra_query="${4:-}"
  local body_file="$TMP_DIR/authorize-body.html"
  local headers_file="$TMP_DIR/authorize-headers.txt"
  local status

  status=$(curl_capture GET "$BASE_URL/authorize?response_type=code&client_id=$client_id&redirect_uri=$redirect_uri&code_challenge=$code_challenge&code_challenge_method=S256&state=test-state&nonce=test-nonce$extra_query" "$body_file" "$headers_file")
  assert_eq 200 "$status" "authorize page"
  extract_session_id "$body_file"
}

login_for_code() {
  local session_id="$1"
  local email="$2"
  local password="$3"
  local body_file="$TMP_DIR/login-body.txt"
  local headers_file="$TMP_DIR/login-headers.txt"
  local status

  status=$(curl_capture POST "$BASE_URL/login" "$body_file" "$headers_file" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$session_id" \
    --data-urlencode "email=$email" \
    --data-urlencode "password=$password")
  assert_eq 302 "$status" "login redirect"
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
  local client_secret="${7:-}"
  local args=(
    -H 'content-type: application/x-www-form-urlencoded'
    --data-urlencode 'grant_type=authorization_code'
    --data-urlencode "code=$code"
    --data-urlencode "code_verifier=$verifier"
    --data-urlencode "redirect_uri=$redirect_uri"
    --data-urlencode "client_id=$client_id"
  )
  if [[ -n "$client_secret" ]]; then
    args+=(--data-urlencode "client_secret=$client_secret")
  fi
  curl_capture POST "$BASE_URL/token" "$body_file" "$headers_file" \
    "${args[@]}"
}

refresh_tokens() {
  local refresh_token="$1"
  local client_id="$2"
  local body_file="$3"
  local headers_file="$4"
  curl_capture POST "$BASE_URL/token" "$body_file" "$headers_file" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=refresh_token' \
    --data-urlencode "refresh_token=$refresh_token" \
    --data-urlencode "client_id=$client_id"
}

echo "==> Starting integration workload"
start_wash_dev

ADMIN_EMAIL="admin.$(date +%s)@example.com"
ADMIN_PASSWORD='changeme123'
ADMIN_NAME='Authority Admin'

echo "==> Verifying request correlation headers"
HEALTH_BODY="$TMP_DIR/healthz.json"
HEALTH_HEADERS="$TMP_DIR/healthz.headers"
status=$(curl_capture GET "$BASE_URL/healthz" "$HEALTH_BODY" "$HEALTH_HEADERS")
assert_eq 200 "$status" "healthz request id"
GENERATED_REQUEST_ID=$(header_value "$HEALTH_HEADERS" x-request-id)
assert_matches "$GENERATED_REQUEST_ID" '^[0-9a-f]{32}$' 'generated x-request-id format'

CUSTOM_REQUEST_BODY="$TMP_DIR/healthz-custom.json"
CUSTOM_REQUEST_HEADERS="$TMP_DIR/healthz-custom.headers"
status=$(curl_capture GET "$BASE_URL/healthz" "$CUSTOM_REQUEST_BODY" "$CUSTOM_REQUEST_HEADERS" \
  -H 'x-request-id: authority-test-request')
assert_eq 200 "$status" "custom request id"
assert_eq authority-test-request "$(header_value "$CUSTOM_REQUEST_HEADERS" x-request-id)" "echo custom x-request-id"

echo "==> Verifying anonymous readiness stays sanitized"
READYZ_PUBLIC_BODY="$TMP_DIR/readyz-public.json"
READYZ_PUBLIC_HEADERS="$TMP_DIR/readyz-public.headers"
status=$(curl_capture GET "$BASE_URL/readyz" "$READYZ_PUBLIC_BODY" "$READYZ_PUBLIC_HEADERS")
assert_eq 200 "$status" "public readyz"
assert_eq true "$(json_get "$READYZ_PUBLIC_BODY" ok)" "public readyz ok"
if grep -Fq '"checks"' "$READYZ_PUBLIC_BODY"; then
  fail "public readyz should not expose detailed checks"
fi

echo "==> Registering admin (bootstrap hook promotes to superadmin)"
ADMIN_TOKEN=$(register_and_login_superadmin "$ADMIN_EMAIL" "$ADMIN_PASSWORD" "$ADMIN_NAME")
assert_ne "" "$ADMIN_TOKEN" "admin access token"

TENANTS_BODY="$TMP_DIR/tenants.json"
TENANTS_HEADERS="$TMP_DIR/tenants.headers"
status=$(curl_capture GET "$BASE_URL/api/tenants" "$TENANTS_BODY" "$TENANTS_HEADERS" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
assert_eq 200 "$status" "management access with admin token"

echo "==> Verifying authenticated readiness exposes operator detail"
READYZ_ADMIN_BODY="$TMP_DIR/readyz-admin.json"
READYZ_ADMIN_HEADERS="$TMP_DIR/readyz-admin.headers"
status=$(curl_capture GET "$BASE_URL/readyz" "$READYZ_ADMIN_BODY" "$READYZ_ADMIN_HEADERS" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
assert_eq 200 "$status" "admin readyz"
assert_eq true "$(json_get "$READYZ_ADMIN_BODY" checks.core_service)" "admin readyz core service"
assert_eq true "$(json_get "$READYZ_ADMIN_BODY" checks.keyvalue)" "admin readyz keyvalue"
assert_eq true "$(json_get "$READYZ_ADMIN_BODY" checks.keys_loaded)" "admin readyz keys loaded"
assert_ne "" "$(json_get "$READYZ_ADMIN_BODY" details.core_service.current_kid)" "admin readyz current kid"
assert_ne "" "$(json_get "$READYZ_ADMIN_BODY" details.core_service.current_key_age_secs)" "admin readyz key age"
assert_ne "" "$(json_get "$READYZ_ADMIN_BODY" details.core_service.rate_limiter_size)" "admin readyz rate limiter size"
assert_ne "" "$(json_get "$READYZ_ADMIN_BODY" details.keyvalue.latency_ms)" "admin readyz kv latency"

echo "==> Creating alternate client for audience scoping"
ALT_REDIRECT_URI='http://localhost:8000/callback2'
ALT_CLIENT_INFO=$(create_client "$ADMIN_TOKEN" 'Scoped Audience Test' "$ALT_REDIRECT_URI")
ALT_CLIENT_ID="${ALT_CLIENT_INFO%%|*}"

echo "==> Creating confidential client for token introspection"
INTROSPECT_REDIRECT_URI='http://localhost:8000/introspect-callback'
INTROSPECT_CLIENT_INFO=$(create_client "$ADMIN_TOKEN" 'Introspection Client' "$INTROSPECT_REDIRECT_URI" true)
INTROSPECT_CLIENT_ID="${INTROSPECT_CLIENT_INFO%%|*}"
INTROSPECT_CLIENT_SECRET="${INTROSPECT_CLIENT_INFO#*|}"
assert_ne "" "$INTROSPECT_CLIENT_SECRET" "confidential client secret"

echo "==> Verifying audit query API"
AUDIT_ALL_BODY="$TMP_DIR/audit-all.json"
AUDIT_ALL_HEADERS="$TMP_DIR/audit-all.headers"
status=$(query_audit "$ADMIN_TOKEN" "$BASE_URL/api/audit?limit=10" "$AUDIT_ALL_BODY" "$AUDIT_ALL_HEADERS")
assert_eq 200 "$status" "audit query all"
assert_eq 10 "$(json_get "$AUDIT_ALL_BODY" filters.limit)" "audit limit echo"
assert_contains_file '"event_type":"client_created"' "$AUDIT_ALL_BODY" 'audit all includes client_created'

AUDIT_FILTER_BODY="$TMP_DIR/audit-filter.json"
AUDIT_FILTER_HEADERS="$TMP_DIR/audit-filter.headers"
status=$(query_audit "$ADMIN_TOKEN" "$BASE_URL/api/audit?event_type=client_created&target_id=$INTROSPECT_CLIENT_ID&limit=5" "$AUDIT_FILTER_BODY" "$AUDIT_FILTER_HEADERS")
assert_eq 200 "$status" "audit query filter"
assert_contains_file '"event_type":"client_created"' "$AUDIT_FILTER_BODY" 'filtered audit event type'
assert_contains_file "\"target_id\":\"$INTROSPECT_CLIENT_ID\"" "$AUDIT_FILTER_BODY" 'filtered audit target'

AUDIT_RANGE_BODY="$TMP_DIR/audit-range.json"
AUDIT_RANGE_HEADERS="$TMP_DIR/audit-range.headers"
CURRENT_TS=$(date +%s)
status=$(query_audit "$ADMIN_TOKEN" "$BASE_URL/api/audit?since=$((CURRENT_TS-120))&until=$CURRENT_TS&limit=20" "$AUDIT_RANGE_BODY" "$AUDIT_RANGE_HEADERS")
assert_eq 200 "$status" "audit query range"

AUDIT_BAD_LIMIT_BODY="$TMP_DIR/audit-bad-limit.json"
AUDIT_BAD_LIMIT_HEADERS="$TMP_DIR/audit-bad-limit.headers"
status=$(query_audit "$ADMIN_TOKEN" "$BASE_URL/api/audit?limit=0" "$AUDIT_BAD_LIMIT_BODY" "$AUDIT_BAD_LIMIT_HEADERS")
if [[ "$status" == "200" ]]; then
  fail "audit query unexpectedly accepted invalid limit"
fi
assert_contains_file 'limit must be at least 1' "$AUDIT_BAD_LIMIT_BODY" 'audit invalid limit rejection'

echo "==> Running lid-admin auth code flow"
CLAIMS_JSON='{"id_token":{"given_name":null,"family_name":null,"preferred_username":null},"userinfo":{"email":null,"role":null,"auth_time":null,"amr":null}}'
CLAIMS_ENCODED=$(python3 - "$CLAIMS_JSON" <<'PY'
import sys
import urllib.parse

print(urllib.parse.quote(sys.argv[1], safe=''))
PY
)
ADMIN_VERIFIER=$(random_string)
ADMIN_CHALLENGE=$(pkce_challenge "$ADMIN_VERIFIER")
ADMIN_SESSION_ID=$(authorize_session 'lid-admin' 'http://localhost:8000/callback' "$ADMIN_CHALLENGE" "&scope=openid+offline_access&claims=$CLAIMS_ENCODED")

echo "==> Recording failed login and login rate-limit metrics"
FAILED_LOGIN_BODY="$TMP_DIR/login-failed.html"
FAILED_LOGIN_HEADERS="$TMP_DIR/login-failed.headers"
status=$(curl_capture POST "$BASE_URL/login" "$FAILED_LOGIN_BODY" "$FAILED_LOGIN_HEADERS" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "session_id=$ADMIN_SESSION_ID" \
  --data-urlencode 'email=bad-user@example.com' \
  --data-urlencode 'password=wrong-password')
assert_eq 200 "$status" "failed login response"
assert_contains_file 'Invalid email or password' "$FAILED_LOGIN_BODY" 'failed login page'

RATE_LIMIT_VERIFIER=$(random_string)
RATE_LIMIT_CHALLENGE=$(pkce_challenge "$RATE_LIMIT_VERIFIER")
RATE_LIMIT_SESSION_ID=$(authorize_session 'lid-admin' 'http://localhost:8000/callback' "$RATE_LIMIT_CHALLENGE")
for attempt in $(seq 1 10); do
  RATE_LIMIT_BODY="$TMP_DIR/login-rate-$attempt.html"
  RATE_LIMIT_HEADERS="$TMP_DIR/login-rate-$attempt.headers"
  status=$(curl_capture POST "$BASE_URL/login" "$RATE_LIMIT_BODY" "$RATE_LIMIT_HEADERS" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$RATE_LIMIT_SESSION_ID" \
    --data-urlencode 'email=missing-user@example.com' \
    --data-urlencode 'password=wrong-password')
  assert_eq 200 "$status" "pre-limit login attempt $attempt"
done
RATE_LIMIT_BODY="$TMP_DIR/login-rate-limit.html"
RATE_LIMIT_HEADERS="$TMP_DIR/login-rate-limit.headers"
status=$(curl_capture POST "$BASE_URL/login" "$RATE_LIMIT_BODY" "$RATE_LIMIT_HEADERS" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "session_id=$RATE_LIMIT_SESSION_ID" \
  --data-urlencode 'email=missing-user@example.com' \
  --data-urlencode 'password=wrong-password')
assert_eq 200 "$status" "rate-limited login attempt"
assert_contains_file 'Too many login attempts' "$RATE_LIMIT_BODY" 'login rate limit page'

ADMIN_CODE=$(login_for_code "$ADMIN_SESSION_ID" "$ADMIN_EMAIL" "$ADMIN_PASSWORD")

TOKEN_BODY="$TMP_DIR/token.json"
TOKEN_HEADERS="$TMP_DIR/token.headers"
status=$(exchange_code "$ADMIN_CODE" "$ADMIN_VERIFIER" 'http://localhost:8000/callback' 'lid-admin' "$TOKEN_BODY" "$TOKEN_HEADERS")
assert_eq 200 "$status" "authorization code exchange"
ACCESS_TOKEN=$(json_get "$TOKEN_BODY" access_token)
ID_TOKEN=$(json_get "$TOKEN_BODY" id_token)
REFRESH_TOKEN=$(json_get "$TOKEN_BODY" refresh_token)
AUTH_TIME=$(jwt_claim "$ID_TOKEN" auth_time)
IAT=$(jwt_claim "$ID_TOKEN" iat)
assert_int_delta_le "$AUTH_TIME" "$IAT" 1 "initial id_token auth_time should be freshly minted"
assert_eq pwd "$(jwt_claim "$ID_TOKEN" amr.0)" "initial id_token amr should record password auth"
assert_eq "" "$(jwt_claim_optional "$ID_TOKEN" acr)" "initial id_token should omit acr for single-factor auth"

REPLAY_BODY="$TMP_DIR/token-replay.json"
REPLAY_HEADERS="$TMP_DIR/token-replay.headers"
status=$(exchange_code "$ADMIN_CODE" "$ADMIN_VERIFIER" 'http://localhost:8000/callback' 'lid-admin' "$REPLAY_BODY" "$REPLAY_HEADERS")
if [[ "$status" == "200" ]]; then
  fail "authorization code replay unexpectedly succeeded"
fi
assert_contains_file 'invalid or expired code' "$REPLAY_BODY" 'authorization code replay rejection'

echo "==> Verifying refresh rotation"
sleep 1
REFRESH_BODY="$TMP_DIR/refresh.json"
REFRESH_HEADERS="$TMP_DIR/refresh.headers"
status=$(refresh_tokens "$REFRESH_TOKEN" 'lid-admin' "$REFRESH_BODY" "$REFRESH_HEADERS")
assert_eq 200 "$status" "refresh token exchange"
NEW_REFRESH_TOKEN=$(json_get "$REFRESH_BODY" refresh_token)
assert_ne "$REFRESH_TOKEN" "$NEW_REFRESH_TOKEN" "refresh token rotation"
REFRESH_ID_TOKEN=$(json_get "$REFRESH_BODY" id_token)
REFRESH_AUTH_TIME=$(jwt_claim "$REFRESH_ID_TOKEN" auth_time)
REFRESH_IAT=$(jwt_claim "$REFRESH_ID_TOKEN" iat)
assert_eq "$AUTH_TIME" "$REFRESH_AUTH_TIME" "refresh id_token should preserve original auth_time"
assert_ne "$REFRESH_AUTH_TIME" "$REFRESH_IAT" "refresh id_token should not restamp auth_time to new iat"
assert_eq pwd "$(jwt_claim "$REFRESH_ID_TOKEN" amr.0)" "refresh id_token should preserve amr"
assert_eq "" "$(jwt_claim_optional "$REFRESH_ID_TOKEN" acr)" "refresh id_token should still omit acr for single-factor auth"

echo "==> Verifying authorize accepts max_age and still produces a fresh auth_time"
MAX_AGE_VERIFIER=$(random_string)
MAX_AGE_CHALLENGE=$(pkce_challenge "$MAX_AGE_VERIFIER")
MAX_AGE_BODY="$TMP_DIR/max-age-authorize.html"
MAX_AGE_HEADERS="$TMP_DIR/max-age-authorize.headers"
status=$(curl_capture GET "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8000/callback&code_challenge=$MAX_AGE_CHALLENGE&code_challenge_method=S256&state=max-age&nonce=max-age&max_age=0" "$MAX_AGE_BODY" "$MAX_AGE_HEADERS")
assert_eq 200 "$status" "authorize with max_age"
MAX_AGE_SESSION_ID=$(extract_session_id "$MAX_AGE_BODY")
MAX_AGE_CODE=$(login_for_code "$MAX_AGE_SESSION_ID" "$ADMIN_EMAIL" "$ADMIN_PASSWORD")
MAX_AGE_TOKEN_BODY="$TMP_DIR/max-age-token.json"
MAX_AGE_TOKEN_HEADERS="$TMP_DIR/max-age-token.headers"
status=$(exchange_code "$MAX_AGE_CODE" "$MAX_AGE_VERIFIER" 'http://localhost:8000/callback' 'lid-admin' "$MAX_AGE_TOKEN_BODY" "$MAX_AGE_TOKEN_HEADERS")
assert_eq 200 "$status" "max_age code exchange"
MAX_AGE_ID_TOKEN=$(json_get "$MAX_AGE_TOKEN_BODY" id_token)
MAX_AGE_AUTH_TIME=$(jwt_claim "$MAX_AGE_ID_TOKEN" auth_time)
MAX_AGE_IAT=$(jwt_claim "$MAX_AGE_ID_TOKEN" iat)
assert_int_delta_le "$MAX_AGE_AUTH_TIME" "$MAX_AGE_IAT" 1 "max_age login should mint id_token with fresh auth_time"

echo "==> Verifying claims request parameter"
assert_eq Authority "$(jwt_claim "$ID_TOKEN" given_name)" "claims parameter given_name"
assert_eq Admin "$(jwt_claim "$ID_TOKEN" family_name)" "claims parameter family_name"
assert_matches "$(jwt_claim "$ID_TOKEN" preferred_username)" '^admin\.[0-9]+$' 'claims parameter preferred_username'

CLAIMS_USERINFO_BODY="$TMP_DIR/claims-userinfo.json"
CLAIMS_USERINFO_HEADERS="$TMP_DIR/claims-userinfo.headers"
status=$(curl_capture GET "$BASE_URL/userinfo" "$CLAIMS_USERINFO_BODY" "$CLAIMS_USERINFO_HEADERS" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
assert_eq 200 "$status" "claims parameter userinfo"
assert_eq "$ADMIN_EMAIL" "$(json_get "$CLAIMS_USERINFO_BODY" email)" "claims parameter userinfo email"
assert_eq superadmin "$(json_get "$CLAIMS_USERINFO_BODY" role)" "claims parameter userinfo role"
assert_ne "" "$(json_get "$CLAIMS_USERINFO_BODY" auth_time)" "claims parameter userinfo auth_time"
assert_eq pwd "$(json_get "$CLAIMS_USERINFO_BODY" amr.0)" "claims parameter userinfo amr"

echo "==> Verifying authorize id_token_hint validation"
HINT_VERIFIER=$(random_string)
HINT_CHALLENGE=$(pkce_challenge "$HINT_VERIFIER")
HINT_BODY="$TMP_DIR/hint-authorize.html"
HINT_HEADERS="$TMP_DIR/hint-authorize.headers"
HINT_ENCODED=$(python3 - "$ID_TOKEN" <<'PY'
import sys
import urllib.parse

print(urllib.parse.quote(sys.argv[1], safe=''))
PY
)
status=$(curl_capture GET "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8000/callback&code_challenge=$HINT_CHALLENGE&code_challenge_method=S256&state=hint-state&nonce=hint-nonce&id_token_hint=$HINT_ENCODED" "$HINT_BODY" "$HINT_HEADERS")
assert_eq 200 "$status" "authorize with id_token_hint"
assert_contains_file "value=\"$ADMIN_EMAIL\"" "$HINT_BODY" 'authorize should prefill hinted email'

BAD_HINT_BODY="$TMP_DIR/hint-invalid-body.txt"
BAD_HINT_HEADERS="$TMP_DIR/hint-invalid-headers.txt"
status=$(curl_capture GET "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8000/callback&code_challenge=$HINT_CHALLENGE&code_challenge_method=S256&state=bad-hint&nonce=hint-nonce&id_token_hint=$ACCESS_TOKEN" "$BAD_HINT_BODY" "$BAD_HINT_HEADERS")
assert_eq 302 "$status" "authorize invalid id_token_hint redirect"
BAD_HINT_LOCATION=$(header_value "$BAD_HINT_HEADERS" location)
assert_matches "$BAD_HINT_LOCATION" 'error=invalid_request' 'invalid id_token_hint error code'
assert_matches "$BAD_HINT_LOCATION" 'error_description=invalid%20id_token_hint' 'invalid id_token_hint description'
assert_matches "$BAD_HINT_LOCATION" 'state=bad-hint' 'invalid id_token_hint preserves state'

echo "==> Verifying token introspection"
INTROSPECT_VERIFIER=$(random_string)
INTROSPECT_CHALLENGE=$(pkce_challenge "$INTROSPECT_VERIFIER")
INTROSPECT_SESSION_ID=$(authorize_session "$INTROSPECT_CLIENT_ID" "$INTROSPECT_REDIRECT_URI" "$INTROSPECT_CHALLENGE")
INTROSPECT_CODE=$(login_for_code "$INTROSPECT_SESSION_ID" "$ADMIN_EMAIL" "$ADMIN_PASSWORD")
INTROSPECT_TOKEN_BODY="$TMP_DIR/introspect-client-token.json"
INTROSPECT_TOKEN_HEADERS="$TMP_DIR/introspect-client-token.headers"
status=$(exchange_code "$INTROSPECT_CODE" "$INTROSPECT_VERIFIER" "$INTROSPECT_REDIRECT_URI" "$INTROSPECT_CLIENT_ID" "$INTROSPECT_TOKEN_BODY" "$INTROSPECT_TOKEN_HEADERS" "$INTROSPECT_CLIENT_SECRET")
assert_eq 200 "$status" "introspection client code exchange"
INTROSPECT_ACCESS_TOKEN=$(json_get "$INTROSPECT_TOKEN_BODY" access_token)

INTROSPECT_ACTIVE_BODY="$TMP_DIR/introspect-active.json"
INTROSPECT_ACTIVE_HEADERS="$TMP_DIR/introspect-active.headers"
status=$(introspect_token "$INTROSPECT_ACCESS_TOKEN" "$INTROSPECT_CLIENT_ID" "$INTROSPECT_CLIENT_SECRET" "$INTROSPECT_ACTIVE_BODY" "$INTROSPECT_ACTIVE_HEADERS")
assert_eq 200 "$status" "active token introspection"
assert_eq true "$(json_get "$INTROSPECT_ACTIVE_BODY" active)" "active introspection response"
assert_eq "$INTROSPECT_CLIENT_ID" "$(json_get "$INTROSPECT_ACTIVE_BODY" client_id)" "introspection client_id"
assert_eq access "$(json_get "$INTROSPECT_ACTIVE_BODY" token_type)" "introspection token_type"
assert_eq "$ADMIN_EMAIL" "$(json_get "$INTROSPECT_ACTIVE_BODY" email)" "introspection email"

INTROSPECT_BAD_AUTH_BODY="$TMP_DIR/introspect-bad-auth.json"
INTROSPECT_BAD_AUTH_HEADERS="$TMP_DIR/introspect-bad-auth.headers"
status=$(introspect_token "$INTROSPECT_ACCESS_TOKEN" "$INTROSPECT_CLIENT_ID" "wrong-secret" "$INTROSPECT_BAD_AUTH_BODY" "$INTROSPECT_BAD_AUTH_HEADERS")
assert_eq 401 "$status" "introspection invalid client auth"
assert_contains_file 'invalid_client' "$INTROSPECT_BAD_AUTH_BODY" 'introspection invalid client error'

echo "==> Verifying scoped bearer validation"
USERINFO_BODY="$TMP_DIR/userinfo.json"
USERINFO_HEADERS="$TMP_DIR/userinfo.headers"
status=$(curl_capture GET "$BASE_URL/userinfo" "$USERINFO_BODY" "$USERINFO_HEADERS" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
assert_eq 200 "$status" "userinfo with access token"
assert_eq "$ADMIN_EMAIL" "$(json_get "$USERINFO_BODY" email)" "userinfo email"

USERINFO_ID_BODY="$TMP_DIR/userinfo-id.json"
USERINFO_ID_HEADERS="$TMP_DIR/userinfo-id.headers"
status=$(curl_capture GET "$BASE_URL/userinfo" "$USERINFO_ID_BODY" "$USERINFO_ID_HEADERS" \
  -H "Authorization: Bearer $ID_TOKEN")
if [[ "$status" == "200" ]]; then
  fail "userinfo unexpectedly accepted id_token"
fi
assert_contains_file 'invalid token type' "$USERINFO_ID_BODY" 'userinfo id_token rejection'

ALT_VERIFIER=$(random_string)
ALT_CHALLENGE=$(pkce_challenge "$ALT_VERIFIER")
ALT_SESSION_ID=$(authorize_session "$ALT_CLIENT_ID" "$ALT_REDIRECT_URI" "$ALT_CHALLENGE")
ALT_CODE=$(login_for_code "$ALT_SESSION_ID" "$ADMIN_EMAIL" "$ADMIN_PASSWORD")
ALT_TOKEN_BODY="$TMP_DIR/alt-token.json"
ALT_TOKEN_HEADERS="$TMP_DIR/alt-token.headers"
status=$(exchange_code "$ALT_CODE" "$ALT_VERIFIER" "$ALT_REDIRECT_URI" "$ALT_CLIENT_ID" "$ALT_TOKEN_BODY" "$ALT_TOKEN_HEADERS")
assert_eq 200 "$status" "alternate client code exchange"
ALT_ACCESS_TOKEN=$(json_get "$ALT_TOKEN_BODY" access_token)

ALT_USERINFO_BODY="$TMP_DIR/alt-userinfo.json"
ALT_USERINFO_HEADERS="$TMP_DIR/alt-userinfo.headers"
status=$(curl_capture GET "$BASE_URL/userinfo" "$ALT_USERINFO_BODY" "$ALT_USERINFO_HEADERS" \
  -H "Authorization: Bearer $ALT_ACCESS_TOKEN")
assert_eq 200 "$status" "userinfo with alternate-client access token"

ALT_TENANTS_BODY="$TMP_DIR/alt-tenants.json"
ALT_TENANTS_HEADERS="$TMP_DIR/alt-tenants.headers"
status=$(curl_capture GET "$BASE_URL/api/tenants" "$ALT_TENANTS_BODY" "$ALT_TENANTS_HEADERS" \
  -H "Authorization: Bearer $ALT_ACCESS_TOKEN")
if [[ "$status" == "200" ]]; then
  fail "management endpoint unexpectedly accepted wrong-audience token"
fi
assert_contains_file 'invalid audience' "$ALT_TENANTS_BODY" 'management audience rejection'

echo "==> Verifying refresh token replay detection"
OLD_REFRESH_BODY="$TMP_DIR/refresh-old.json"
OLD_REFRESH_HEADERS="$TMP_DIR/refresh-old.headers"
status=$(refresh_tokens "$REFRESH_TOKEN" 'lid-admin' "$OLD_REFRESH_BODY" "$OLD_REFRESH_HEADERS")
if [[ "$status" == "200" ]]; then
  fail "old refresh token unexpectedly remained valid"
fi
assert_contains_file 'refresh token' "$OLD_REFRESH_BODY" 'old refresh token rejection'

# After replay detection, all sessions for this user are revoked.
# Verify the access token is now invalid.
REVOKED_BODY="$TMP_DIR/userinfo-revoked.json"
REVOKED_HEADERS="$TMP_DIR/userinfo-revoked.headers"
status=$(curl_capture GET "$BASE_URL/userinfo" "$REVOKED_BODY" "$REVOKED_HEADERS" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
if [[ "$status" == "200" ]]; then
  fail "access token unexpectedly valid after session revocation"
fi
assert_contains_file 'revoked' "$REVOKED_BODY" 'access token revoked after replay'

INTROSPECT_INACTIVE_BODY="$TMP_DIR/introspect-inactive.json"
INTROSPECT_INACTIVE_HEADERS="$TMP_DIR/introspect-inactive.headers"
status=$(introspect_token "$ACCESS_TOKEN" "$INTROSPECT_CLIENT_ID" "$INTROSPECT_CLIENT_SECRET" "$INTROSPECT_INACTIVE_BODY" "$INTROSPECT_INACTIVE_HEADERS")
assert_eq 200 "$status" "inactive token introspection"
assert_eq false "$(json_get "$INTROSPECT_INACTIVE_BODY" active)" "inactive introspection response"

echo "==> Verifying metrics endpoint"
METRICS_VERIFIER=$(random_string)
METRICS_CHALLENGE=$(pkce_challenge "$METRICS_VERIFIER")
METRICS_SESSION_ID=$(authorize_session 'lid-admin' 'http://localhost:8000/callback' "$METRICS_CHALLENGE")
METRICS_CODE=$(login_for_code "$METRICS_SESSION_ID" "$ADMIN_EMAIL" "$ADMIN_PASSWORD")
METRICS_TOKEN_BODY="$TMP_DIR/metrics-token.json"
METRICS_TOKEN_HEADERS="$TMP_DIR/metrics-token.headers"
status=$(exchange_code "$METRICS_CODE" "$METRICS_VERIFIER" 'http://localhost:8000/callback' 'lid-admin' "$METRICS_TOKEN_BODY" "$METRICS_TOKEN_HEADERS")
assert_eq 200 "$status" "metrics auth code exchange"
METRICS_ACCESS_TOKEN=$(json_get "$METRICS_TOKEN_BODY" access_token)

METRICS_BODY="$TMP_DIR/metrics.txt"
METRICS_HEADERS="$TMP_DIR/metrics.headers"
status=$(curl_capture GET "$BASE_URL/metrics" "$METRICS_BODY" "$METRICS_HEADERS" \
  -H "Authorization: Bearer $METRICS_ACCESS_TOKEN")
assert_eq 200 "$status" "metrics scrape"
assert_contains_file '# TYPE lattice_id_login_attempts_total counter' "$METRICS_BODY" 'login metrics family'
assert_contains_file '# TYPE lattice_id_token_issued_total counter' "$METRICS_BODY" 'token issuance metrics family'
assert_contains_file '# TYPE lattice_id_core_request_duration_ms histogram' "$METRICS_BODY" 'core latency metrics family'
assert_metric_ge "$METRICS_BODY" 'lattice_id_login_attempts_total' 'flow=password,result=success' 1 'successful password login metric'
assert_metric_ge "$METRICS_BODY" 'lattice_id_login_attempts_total' 'flow=password,result=failure' 1 'failed password login metric'
assert_metric_ge "$METRICS_BODY" 'lattice_id_rate_limit_hits_total' 'scope=login' 1 'login rate limit metric'
assert_metric_ge "$METRICS_BODY" 'lattice_id_token_issued_total' 'grant_type=authorization_code,token_type=access' 1 'authorization code access token metric'
assert_metric_ge "$METRICS_BODY" 'lattice_id_token_issued_total' 'grant_type=refresh_token,token_type=refresh_token' 1 'refresh token issuance metric'
assert_metric_ge "$METRICS_BODY" 'lattice_id_refresh_usage_total' 'result=success' 1 'refresh success metric'
assert_metric_ge "$METRICS_BODY" 'lattice_id_refresh_usage_total' 'result=replay_detected' 1 'refresh replay metric'

echo "PASS: bootstrap, audit query, code exchange, introspection, auth_time semantics, refresh rotation, metrics, scoped bearer, and replay detection"