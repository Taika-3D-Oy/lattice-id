#!/usr/bin/env bash
# Test: MFA flow integration (3.6)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

# Python helper to generate current TOTP code
generate_mfa_code() {
  local secret="$1"
  python3 - "$secret" <<'PY'
import sys
import base64
import hashlib
import hmac
import time
import struct

def compute_totp(secret_b32):
    # RFC 4226 / 6238
    secret = base64.b32decode(secret_b32.upper())
    time_step = int(time.time() / 30)
    msg = struct.pack(">Q", time_step)
    
    mac = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = mac[19] & 0x0f
    code = struct.unpack(">I", mac[offset:offset+4])[0] & 0x7fffffff
    otp = code % 1000000
    return f"{otp:06d}"

print(compute_totp(sys.argv[1]))
PY
}

echo "==> Starting MFA integration test"
start_wash_dev

# 1. Register admin (bootstrap hook promotes to superadmin)
ADMIN_EMAIL="mfa.admin@example.com"
ADMIN_PASSWORD='password123'
ADMIN_NAME='MFA Admin'
ADMIN_TOKEN=$(register_and_login_superadmin "$ADMIN_EMAIL" "$ADMIN_PASSWORD" "$ADMIN_NAME")

ADMIN_SUB=$(curl -sS -X GET "$BASE_URL/userinfo" -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -c "import sys, json; print(json.load(sys.stdin)['sub'])")

# 2. Setup MFA
echo "==> Setting up MFA"
MFA_SETUP_BODY="$TMP_DIR/mfa-setup.json"
status=$(curl -sS -o "$MFA_SETUP_BODY" -w '%{http_code}' -X POST "$BASE_URL/api/users/$ADMIN_SUB/mfa/setup" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
assert_eq 200 "$status" "MFA setup"
MFA_SECRET=$(json_get "$MFA_SETUP_BODY" secret)

# 3. Confirm MFA (using generated code)
echo "==> Confirming MFA"
CODE=$(generate_mfa_code "$MFA_SECRET")
MFA_CONFIRM_BODY="$TMP_DIR/mfa-confirm.json"
status=$(curl -sS -o "$MFA_CONFIRM_BODY" -w '%{http_code}' -X POST "$BASE_URL/api/users/$ADMIN_SUB/mfa/confirm" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'content-type: application/json' \
    -d "{\"code\":\"$CODE\"}")
assert_eq 200 "$status" "MFA confirm"
RECOVERY_CODE=$(python3 -c "import sys, json; print(json.load(open('$MFA_CONFIRM_BODY'))['recovery_codes'][0])")

# 4. Test MFA login flow (TOTP)
echo "==> Testing MFA Login (TOTP)"
# Start auth code flow
VERIFIER=$(random_string)
CHALLENGE=$(python3 -c "import base64, hashlib, sys; digest = hashlib.sha256(sys.argv[1].encode('utf-8')).digest(); print(base64.urlsafe_b64encode(digest).decode('ascii').rstrip('='))" "$VERIFIER")
AUTH_PAGE_BODY="$TMP_DIR/auth-page.html"
status=$(curl -sS -o "$AUTH_PAGE_BODY" -w '%{http_code}' -X GET "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8000/callback&scope=openid+offline_access&code_challenge=$CHALLENGE&code_challenge_method=S256&state=mfa-state&nonce=mfa-nonce")
assert_eq 200 "$status" "authorize page"
SESSION_ID=$(python3 -c "import re, sys; m = re.search(r'name=\"session_id\"\s+value=\"([^\"]+)\"', open('$AUTH_PAGE_BODY').read()); print(m.group(1))")

# Login (should redirect to MFA page)
LOGIN_HEADERS="$TMP_DIR/login-headers.txt"
status=$(curl -sS -o /dev/null -D "$LOGIN_HEADERS" -w '%{http_code}' -X POST "$BASE_URL/login" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$SESSION_ID" \
    --data-urlencode "email=$ADMIN_EMAIL" \
    --data-urlencode "password=$ADMIN_PASSWORD")
assert_eq 200 "$status" "login should return MFA page (not redirect yet)"

# Extract MFA token from body if possible or just try to see if body contains MFA prompt
MFA_PAGE_BODY="$TMP_DIR/mfa-page.html"
curl -sS -o "$MFA_PAGE_BODY" -X POST "$BASE_URL/login" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$SESSION_ID" \
    --data-urlencode "email=$ADMIN_EMAIL" \
    --data-urlencode "password=$ADMIN_PASSWORD"

MFA_TOKEN=$(python3 -c "import re, sys; m = re.search(r'name=\"mfa_token\"\s+value=\"([^\"]+)\"', open('$MFA_PAGE_BODY').read()); print(m.group(1))")

# Verify MFA code
CODE=$(generate_mfa_code "$MFA_SECRET")
MFA_VERIFY_HEADERS="$TMP_DIR/mfa-verify-headers.txt"
status=$(curl -sS -o /dev/null -D "$MFA_VERIFY_HEADERS" -w '%{http_code}' -X POST "$BASE_URL/login/mfa" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$SESSION_ID" \
    --data-urlencode "mfa_token=$MFA_TOKEN" \
    --data-urlencode "code=$CODE")
assert_eq 302 "$status" "MFA verification redirect"
LOCATION=$(grep -Ei '^location:' "$MFA_VERIFY_HEADERS" | awk '{print $2}' | tr -d '\r')
CODE_PARAM=$(python3 -c "from urllib.parse import urlparse, parse_qs; print(parse_qs(urlparse('$LOCATION').query)['code'][0])")
assert_ne "" "$CODE_PARAM" "auth code from MFA login"

MFA_TOKEN_BODY="$TMP_DIR/mfa-token.json"
status=$(curl -sS -o "$MFA_TOKEN_BODY" -w '%{http_code}' -X POST "$BASE_URL/token" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode "code=$CODE_PARAM" \
    --data-urlencode "code_verifier=$VERIFIER" \
    --data-urlencode 'redirect_uri=http://localhost:8000/callback' \
    --data-urlencode 'client_id=lid-admin' \
    --data-urlencode 'scope=openid+offline_access')
assert_eq 200 "$status" "MFA token exchange"
MFA_ID_TOKEN=$(json_get "$MFA_TOKEN_BODY" id_token)
assert_eq pwd "$(jwt_claim "$MFA_ID_TOKEN" amr.0)" "MFA id_token primary amr"
assert_eq otp "$(jwt_claim "$MFA_ID_TOKEN" amr.1)" "MFA id_token otp amr"
assert_eq mfa "$(jwt_claim "$MFA_ID_TOKEN" amr.2)" "MFA id_token mfa amr"
assert_eq urn:lattice-id:mfa:totp "$(jwt_claim "$MFA_ID_TOKEN" acr)" "MFA id_token acr"

MFA_REFRESH_TOKEN=$(json_get "$MFA_TOKEN_BODY" refresh_token)
MFA_REFRESH_BODY="$TMP_DIR/mfa-refresh.json"
status=$(curl -sS -o "$MFA_REFRESH_BODY" -w '%{http_code}' -X POST "$BASE_URL/token" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=refresh_token' \
    --data-urlencode "refresh_token=$MFA_REFRESH_TOKEN" \
    --data-urlencode 'client_id=lid-admin')
assert_eq 200 "$status" "MFA refresh token exchange"
MFA_REFRESH_ID_TOKEN=$(json_get "$MFA_REFRESH_BODY" id_token)
assert_eq pwd "$(jwt_claim "$MFA_REFRESH_ID_TOKEN" amr.0)" "MFA refresh id_token primary amr"
assert_eq otp "$(jwt_claim "$MFA_REFRESH_ID_TOKEN" amr.1)" "MFA refresh id_token otp amr"
assert_eq mfa "$(jwt_claim "$MFA_REFRESH_ID_TOKEN" amr.2)" "MFA refresh id_token mfa amr"
assert_eq urn:lattice-id:mfa:totp "$(jwt_claim "$MFA_REFRESH_ID_TOKEN" acr)" "MFA refresh id_token acr"

# 5. Test MFA Login (Recovery Code)
echo "==> Testing MFA Login (Recovery Code)"
# New session
AUTH_PAGE_BODY_2="$TMP_DIR/auth-page-2.html"
curl -sS -o "$AUTH_PAGE_BODY_2" -X GET "$BASE_URL/authorize?response_type=code&client_id=lid-admin&redirect_uri=http://localhost:8000/callback&code_challenge=$CHALLENGE&code_challenge_method=S256&state=mfa-state-2&nonce=mfa-nonce"
SESSION_ID_2=$(python3 -c "import re, sys; m = re.search(r'name=\"session_id\"\s+value=\"([^\"]+)\"', open('$AUTH_PAGE_BODY_2').read()); print(m.group(1))")

MFA_PAGE_BODY_2="$TMP_DIR/mfa-page-2.html"
curl -sS -o "$MFA_PAGE_BODY_2" -X POST "$BASE_URL/login" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$SESSION_ID_2" \
    --data-urlencode "email=$ADMIN_EMAIL" \
    --data-urlencode "password=$ADMIN_PASSWORD"

MFA_TOKEN_2=$(python3 -c "import re, sys; m = re.search(r'name=\"mfa_token\"\s+value=\"([^\"]+)\"', open('$MFA_PAGE_BODY_2').read()); print(m.group(1))")

status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/login/mfa" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "session_id=$SESSION_ID_2" \
    --data-urlencode "mfa_token=$MFA_TOKEN_2" \
    --data-urlencode "code=$RECOVERY_CODE")
assert_eq 302 "$status" "MFA recovery code redirect"

# 6. Disable MFA
echo "==> Disabling MFA"
MFA_DISABLE_BODY="$TMP_DIR/mfa-disable.json"
status=$(curl -sS -o "$MFA_DISABLE_BODY" -w '%{http_code}' -X DELETE "$BASE_URL/api/users/$ADMIN_SUB/mfa" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
assert_eq 200 "$status" "MFA disable"

echo "PASS: MFA integration tests"
