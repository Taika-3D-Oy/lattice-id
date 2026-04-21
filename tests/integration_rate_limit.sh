#!/usr/bin/env bash
# Test: Rate Limiting Integration (3.5)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

trap cleanup EXIT

echo "==> Starting rate limiting integration test"
wait_for_cluster

# 1. Test /register rate limiting (Task 1.4)
# Per lib.rs handle_register: 3 attempts per 1 hour per EMAIL.
echo "==> Testing /register rate limiting (per email)"
EMAIL="rate_limit_test_$(date +%s)@example.com"
for i in {1..3}; do
  status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/register" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"password123\",\"name\":\"Rate $i\"}")
  # The first one should be 201, subsequent ones for SAME email might be "email already registered" (400 probably)
  # But the rate limit should trigger first if we check it before existence.
  # Actually lib.rs checks rate limit BEFORE existence.
  if [[ "$i" -eq 1 ]]; then
    assert_eq 201 "$status" "First registration"
  else
    # It might be 400 because of "email already registered" OR rate limit.
    # We'll check the 4th one specifically for rate limit message.
    :
  fi
done

# 4th attempt should be rate limited
BODY_FILE="$TMP_DIR/register-rate.json"
status=$(curl -s -o "$BODY_FILE" -w '%{http_code}' -X POST "$BASE_URL/register" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"password123\",\"name\":\"Rate 4\"}")

if grep -q "too many registration attempts" "$BODY_FILE"; then
    echo "OK: /register is rate limited per email"
else
    fail "4th registration attempt not rate limited as expected. Status: $status, Body: $(cat "$BODY_FILE")"
fi

# 2. Test /verify/email rate limiting (Task 2.9/1.5 pattern)
# Per lib.rs handle_email_verification: 5 attempts per 1 hour per token.
echo "==> Testing /verify/email rate limiting"
# Need a token. Let's use a dummy token.
DUMMY_TOKEN="dummy_token_$(date +%s)"
for i in {1..5}; do
  status=$(curl -s -o /dev/null -w '%{http_code}' -X GET "$BASE_URL/verify/email?token=$DUMMY_TOKEN")
  # It should be 400 (invalid token) but NOT rate limited yet.
  if [[ "$status" != "400" ]]; then
     fail "Check $i failed with status $status (expected 400)"
  fi
done

# 6th attempt should be rate limited
BODY_FILE="$TMP_DIR/verify-rate.json"
status=$(curl -s -o "$BODY_FILE" -w '%{http_code}' -X GET "$BASE_URL/verify/email?token=$DUMMY_TOKEN")
if grep -q "too many verification attempts" "$BODY_FILE"; then
    echo "OK: /verify/email is rate limited"
else
    fail "6th verify attempt not rate limited as expected. Status: $status, Body: $(cat "$BODY_FILE")"
fi

echo "PASS: Rate limiting integration tests"
